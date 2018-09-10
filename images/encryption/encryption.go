/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package encryption

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
	"strings"

	"github.com/containerd/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

// LayerInfo holds information about an image layer
type LayerInfo struct {
	// The Id of the layer starting at 0
	ID uint32
	// Array of wrapped keys from which KeyIds can be derived
	WrappedKeys [][]byte
	// The Digest of the layer
	Digest string
	// The Encryption method used for encrypting the layer
	Encryption string
	// The size of the layer file
	FileSize int64
	// The platform for which this layer is
	Platform string
}

// LayerFilter holds criteria for which layer to select
type LayerFilter struct {
	// IDs of layers to touch; may be negative number to start from topmost layer
	// empty array means 'all layers'
	Layers []int32
	// Platforms to touch; empty array means 'all platforms'
	Platforms []ocispec.Platform
}

// EncryptConfig is the container image PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type EncryptConfig struct {
	Recipients     []string
	GPGPubRingFile []byte
	Operation      int32
	// for adding recipients on an already encrypted image we need the
	// symmetric keys for the layers so we can wrap them with the recpient's
	// public key
	Dc DecryptConfig
}

const (
	// OperationAddRecipients instructs to add a recipient
	OperationAddRecipients = int32(iota)
	// OperationRemoveRecipients instructs to remove a recipient
	OperationRemoveRecipients = int32(iota)
)

// DecryptKeyData stores private key data for decryption and the necessary password
// for being able to access/decrypt the private key data.
type DecryptKeyData struct {
	SymKeyData   []byte
	SymKeyCipher uint8
}

// DecryptConfig stores the platform and layer number encode in a string as a
// key to the map. The symmetric key needed for decrypting a platform specific
// layer is stored as value.
type DecryptConfig struct {
	LayerSymKeyMap map[string]DecryptKeyData
}

// CryptoConfig is a common wrapper for EncryptConfig and DecrypConfig that can
// be passed through functions that share much code for encryption and decryption
type CryptoConfig struct {
	Ec *EncryptConfig
	Dc *DecryptConfig
}

// createEntityList creates the opengpg EntityList by reading the KeyRing
// first and then filtering out recipients' keys
func createEntityList(ec *EncryptConfig) (openpgp.EntityList, error) {
	r := bytes.NewReader(ec.GPGPubRingFile)

	entityList, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	rSet := make(map[string]int)
	for _, r := range ec.Recipients {
		rSet[r] = 0
	}

	var filteredList openpgp.EntityList
	for _, entity := range entityList {
		for k := range entity.Identities {
			addr, err := mail.ParseAddress(k)
			if err != nil {
				return nil, err
			}
			for _, r := range ec.Recipients {
				if strings.Compare(addr.Name, r) == 0 || strings.Compare(addr.Address, r) == 0 {
					filteredList = append(filteredList, entity)
					rSet[r] = rSet[r] + 1
				}
			}
		}
	}

	// make sure we found keys for all the Recipients...
	var buffer bytes.Buffer
	notFound := false
	buffer.WriteString("No key found for the following recipients: ")

	for k, v := range rSet {
		if v == 0 {
			if notFound {
				buffer.WriteString(", ")
			}
			buffer.WriteString(k)
			notFound = true
		}
	}

	if notFound {
		return nil, errors.Wrapf(errdefs.ErrNotFound, buffer.String())
	}

	return filteredList, nil
}

func getSymKeyParameters(layerSymKeyMap map[string]DecryptKeyData, index string) ([]byte, packet.CipherFunction) {
	v, ok := layerSymKeyMap[index]
	if !ok {
		return nil, packet.CipherFunction(0)
	}
	return v.SymKeyData, packet.CipherFunction(v.SymKeyCipher)
}

// assembleEncryptedMessage takes in the openpgp encrypted body packets and
// assembles the openpgp message
func assembleEncryptedMessage(encBody []byte, keys [][]byte) []byte {
	encMsg := make([]byte, 0)

	for _, k := range keys {
		encMsg = append(encMsg, k...)
	}
	encMsg = append(encMsg, encBody...)

	return encMsg
}

// HandleEncrypt encrypts a byte array using data from the EncryptConfig. It
// also manages the list of recipients' keys by enabling removal or addition
// of recipients.
func HandleEncrypt(ec *EncryptConfig, data []byte, keys [][]byte, layerNum int32, platform string) ([]byte, [][]byte, error) {
	var (
		encBlob     []byte
		wrappedKeys [][]byte
		err         error
	)

	filteredList, err := createEntityList(ec)
	if err != nil {
		return nil, nil, err
	}
	if len(filteredList) == 0 {
		return nil, nil, errors.Wrapf(errdefs.ErrInvalidArgument, "No keys were found to encrypt message to.\n")
	}

	switch ec.Operation {
	case OperationAddRecipients:
		if len(keys) > 0 {
			index := fmt.Sprintf("%s:%d", platform, layerNum)
			symKey, symKeyCipher := getSymKeyParameters(ec.Dc.LayerSymKeyMap, index)
			if len(symKey) == 0 {
				return nil, nil, errors.Wrapf(errdefs.ErrInvalidArgument, "Unable to retrieve symkey for layer %s", index)
			}
			wrappedKeys, err = addRecipientsToKeys(keys, filteredList, symKey, symKeyCipher, nil)
		} else {
			encBlob, wrappedKeys, err = encryptData(data, filteredList, nil)
		}
	case OperationRemoveRecipients:
		wrappedKeys, err = removeRecipientsFromKeys(keys, filteredList)
		// encBlob stays empty to indicate it wasn't touched
	}

	if err != nil {
		return nil, nil, err
	}

	return encBlob, wrappedKeys, nil
}

// Decrypt decrypts a byte array using data from the DecryptConfig
// The encrypted bulk data is provided in encBody and the wrapped
// keys were taken from the OCI Descriptor. The OpenPGP message
// is reassembled from the encBody and wrapped key.
// The layerNum and platform are used to pick the symmetric key
// used for decrypting the layer given its number and platform.
func Decrypt(dc *DecryptConfig, encBody []byte, keys [][]byte, layerNum int32, platform string) ([]byte, error) {

	data := assembleEncryptedMessage(encBody, keys)

	index := fmt.Sprintf("%s:%d", platform, layerNum)
	symKey, symKeyCipher := getSymKeyParameters(dc.LayerSymKeyMap, index)
	if len(symKey) == 0 {
		return nil, errors.Wrapf(errdefs.ErrInvalidArgument, "Unable to retrieve symkey for layer %s", index)
	}

	r := bytes.NewReader(data)
	md, err := ReadMessage(r, symKey, symKeyCipher)
	if err != nil {
		return []byte{}, err
	}
	return ioutil.ReadAll(md.UnverifiedBody)
}

// GetSymmetricKeys walks the list of layerInfos and tries to decrypt the
// wrapped symmetric keys. For this it determines whether private keys are
// in the GPGVault or on this system and prompts for the passwords for those
// that are available. If we do not find a private key on the system for
// getting to the symmetric key of a layer then an error is generated.
// Otherwise the wrapped symmetric key is decrypted using the private key and
// added to a map that describes the layer by platform name and layer number
// as key and the symmetric key data as value.
func GetSymmetricKeys(layerInfos []LayerInfo, gpgClient GPGClient, gpgVault GPGVault) (map[string]DecryptKeyData, error) {
	type PrivKeyData struct {
		KeyData         []byte
		KeyDataPassword []byte
	}
	var pkd PrivKeyData
	keyIDPasswordMap := make(map[uint64]PrivKeyData)
	layerSymkeyMap := make(map[string]DecryptKeyData)

	// we need to decrypt one symmetric key per encrypted layer per platform
	for _, layerInfo := range layerInfos {

		keyIds, err := WrappedKeysToKeyIds(layerInfo.WrappedKeys)
		if err != nil {
			return layerSymkeyMap, err
		}

		found := false
		for _, keyid := range keyIds {
			// do we have this key? -- first check the vault
			if gpgVault != nil {
				_, keydata := gpgVault.GetGPGPrivateKey(keyid)
				if len(keydata) > 0 {
					pkd = PrivKeyData{
						KeyData:         keydata,
						KeyDataPassword: nil, // password not supported in this case
					}
					keyIDPasswordMap[keyid] = pkd
				}
			} else if gpgClient != nil {
				// check the local system's gpg installation
				keyinfo, haveKey, _ := gpgClient.GetSecretKeyDetails(keyid)
				// this may fail if the key is not here; we ignore the error
				if !haveKey {
					// key not on this system
					continue
				}

				var ok bool
				if pkd, ok = keyIDPasswordMap[keyid]; !ok {
					fmt.Printf("Passphrase required for Key id 0x%x: \n%v", keyid, string(keyinfo))
					fmt.Printf("Enter passphrase for key with Id 0x%x: ", keyid)

					password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
					fmt.Printf("\n")
					if err != nil {
						return layerSymkeyMap, err
					}
					keydata, err := gpgClient.GetGPGPrivateKey(keyid, string(password))
					if err != nil {
						return layerSymkeyMap, err
					}
					pkd = PrivKeyData{
						KeyData:         keydata,
						KeyDataPassword: password,
					}
					keyIDPasswordMap[keyid] = pkd
				}
			} else {
				return layerSymkeyMap, errors.Wrapf(errdefs.ErrInvalidArgument, "No GPGVault or GPGClient passed.")
			}
			symKeyData, symKeyCipher, err := DecryptSymmetricKey(layerInfo.WrappedKeys, keyid, pkd.KeyData, pkd.KeyDataPassword, nil)
			if err != nil {
				return layerSymkeyMap, err
			}

			index := fmt.Sprintf("%s:%d", layerInfo.Platform, layerInfo.ID)
			layerSymkeyMap[index] = DecryptKeyData{
				SymKeyData:   symKeyData,
				SymKeyCipher: uint8(symKeyCipher),
			}
			found = true
			break
		}
		if !found && len(layerInfo.WrappedKeys) > 0 {
			keyIds, _ := WrappedKeysToKeyIds(layerInfo.WrappedKeys)
			ids := Uint64ToStringArray("0x%x", keyIds)

			return layerSymkeyMap, errors.Wrapf(errdefs.ErrNotFound, "Missing key for decryption of layer %d of %s. Need one of the following keys: %s", layerInfo.ID, layerInfo.Platform, strings.Join(ids, ", "))
		}
	}
	return layerSymkeyMap, nil
}

// EncodeWrappedKeys encodes wrapped openpgp keys to a string readable ','
// separated base64 strings.
func EncodeWrappedKeys(keys [][]byte) string {
	var keyArray []string

	for _, k := range keys {
		keyArray = append(keyArray, base64.StdEncoding.EncodeToString(k))
	}

	return strings.Join(keyArray, ",")
}

// DecodeWrappedKeys decodes wrapped openpgp keys from string readable ','
// separated base64 strings to their byte values
func DecodeWrappedKeys(keys string) ([][]byte, error) {
	keySplit := strings.Split(keys, ",")
	keyBytes := make([][]byte, 0, len(keySplit))

	for _, v := range keySplit {
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		keyBytes = append(keyBytes, data)
	}

	return keyBytes, nil
}
