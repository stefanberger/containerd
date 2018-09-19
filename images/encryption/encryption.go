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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/mail"
	"os"
	"strconv"
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
	WrappedKeys string
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
	// map holding 'gpg-recipients' and 'gpg-pubkeyringfile'
	Parameters map[string]string

	Operation  int32
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

const (
	DefaultEncryptionScheme = "pgp"
)

// DecryptKeyData stores private key data for decryption and the necessary password
// for being able to access/decrypt the private key data.
type DecryptKeyData struct {
	SymKeyData   []byte
	SymKeyCipher uint8
}

// DecryptConfig stores the platform and layer number encoded in a string as a
// key to the map. The symmetric key needed for decrypting a platform specific
// layer is stored as value.
type DecryptConfig struct {
	Parameters map[string]string
}

// CryptoConfig is a common wrapper for EncryptConfig and DecrypConfig that can
// be passed through functions that share much code for encryption and decryption
type CryptoConfig struct {
	Ec *EncryptConfig
	Dc *DecryptConfig
}

// LayerEncryptor is the interface used for encryting and decrypting layers using
// a specific encryption technology (pgp, jwe)
type LayerEncryptor interface {
	HandleEncrypt(ec *EncryptConfig, planeLayer []byte, wrappedKeys string) ([]byte, string, error)
	Decrypt(dc *DecryptConfig, encLayer []byte, wrappedKeys string) ([]byte, error)
	GetAnnotationID() string

	GetKeyIdsFromWrappedKeys(wrappedKeys string) ([]uint64, [][]byte, error)
	GetRecipients(wrappedKeys string) ([]string, error)
}

func init() {
	encryptors = make(map[string]LayerEncryptor)
	registerLayerEncryptor("pgp", &pgpLayerEncryptor{})
}

var encryptors map[string]LayerEncryptor

func registerLayerEncryptor(scheme string, iface LayerEncryptor) {
	encryptors[scheme] = iface
}

// GetEncryptor looks up the encryptor interface given an encryption scheme (gpg, jwe)
func GetEncryptor(scheme string) LayerEncryptor {
	return encryptors[scheme]
}

type pgpLayerEncryptor struct {
}

// commonEncryptLayer is a function to encrypt the plain layer using a new random
// symmetric key and return the LayerBlockCipherHandler's JSON in string form for
// later use during decryption
func commonEncryptLayer(plainLayer []byte, typ LayerCipherType) ([]byte, []byte, error) {
	symKey := make([]byte, 256/8)
	_, err := io.ReadFull(rand.Reader, symKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not create symmetric key")
	}
	opts := LayerBlockCipherOptions {
		SymmetricKey: symKey,
	}
	lbch, err := NewLayerBlockCipherHandler()
	if err != nil {
		return nil, nil, err
	}

	encLayer, opts, err := lbch.Encrypt(plainLayer, typ, opts)
	if err != nil {
		return nil, nil, err
	}

	optsData, err := json.Marshal(opts)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not JSON marshal opts")
	}
	return encLayer, optsData, err
}

// commonDecryptLayer decrypts an encrypted layer previously encrypted with commonEncryptLayer
// by passing along the optsData
func commonDecryptLayer(encLayer []byte, optsData []byte) ([]byte, error) {
	opts := LayerBlockCipherOptions{}
	err := json.Unmarshal(optsData, &opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not JSON unmarshal optsData")
	}

	lbch, err := NewLayerBlockCipherHandler()
	if err != nil {
		return nil, err
	}

	plainLayer, opts, err := lbch.Decrypt(encLayer, opts)
	if err != nil {
		return nil, err
	}
	
	return plainLayer, nil
}

// createEntityList creates the opengpg EntityList by reading the KeyRing
// first and then filtering out recipients' keys
func (le *pgpLayerEncryptor) createEntityList(ec *EncryptConfig) (openpgp.EntityList, error) {
	gpgpubringfile, err := base64.StdEncoding.DecodeString(ec.Parameters["gpg-pubkeyringfile"])
	if err != nil {
		return nil, errors.Wrapf(err, "")
	}
	r := bytes.NewReader(gpgpubringfile)

	entityList, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	recipients := strings.Split(ec.Parameters["gpg-recipients"], ",") 
	rSet := make(map[string]int)
	for _, r := range recipients {
		rSet[r] = 0
	}

	var filteredList openpgp.EntityList
	for _, entity := range entityList {
		for k := range entity.Identities {
			addr, err := mail.ParseAddress(k)
			if err != nil {
				return nil, err
			}
			for _, r := range recipients {
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

// assembleEncryptedMessage takes in the openpgp encrypted body packets and
// assembles the openpgp message
func (le *pgpLayerEncryptor) assembleEncryptedMessage(encBody []byte, keys [][]byte) []byte {
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
func (le *pgpLayerEncryptor) HandleEncrypt(ec *EncryptConfig, plainLayer []byte, wrappedKeys string) ([]byte, string, error) {
	var (
		encLayer []byte
		err      error
	)
	keys, pgpTail, err := le.decodeWrappedKeys(wrappedKeys)
	if err != nil {
		return nil, "", err
	}

	filteredList, err := le.createEntityList(ec)
	if err != nil {
		return nil, "", err
	}
	if len(filteredList) == 0 {
		return nil, "", errors.Wrapf(errdefs.ErrInvalidArgument, "No keys were found to encrypt message to.\n")
	}

	switch ec.Operation {
	case OperationAddRecipients:
		if len(keys) > 0 {
			symKey, symKeyCipher, err := le.getSymKeyParameters(ec.Dc.Parameters, keys)
			if err != nil {
				return nil, "", err
			}
			keys, err = pgpAddRecipientsToKeys(keys, filteredList, symKey, symKeyCipher, nil)
		} else {
			var optsData []byte
			// first encrypt the data with a symmetric key
			encLayer, optsData, err = commonEncryptLayer(plainLayer, AeadAes256Gcm)
			if err == nil {
				// then encrypt the returned options that hold the key, IV, etc.
				pgpTail, keys, err = pgpEncryptData(optsData, filteredList, nil)
			}
		}
	case OperationRemoveRecipients:
		keys, err = pgpRemoveRecipientsFromKeys(keys, filteredList)
		// encBlob stays empty to indicate it wasn't touched
	}

	if err != nil {
		return nil, "", err
	}

	wrappedKeys = le.encodeWrappedKeys(keys, pgpTail)

	return encLayer, wrappedKeys, nil
}

// Decrypt decrypts a byte array using data from the DecryptConfig
// The encrypted bulk data is provided in encBody and the wrapped
// keys were taken from the OCI Descriptor. The OpenPGP message
// is reassembled from the encBody and wrapped key.
// The layerNum and platform are used to pick the symmetric key
// used for decrypting the layer given its number and platform.
func (le *pgpLayerEncryptor) Decrypt(dc *DecryptConfig, encLayer []byte, wrappedKeys string) ([]byte, error) {

	keys, pgpTail, err := le.decodeWrappedKeys(wrappedKeys)
	if err != nil {
		return nil, err
	}

	symKey, symKeyCipher, err := le.getSymKeyParameters(dc.Parameters, keys)

	data := le.assembleEncryptedMessage(pgpTail, keys)
	r := bytes.NewReader(data)
	md, err := PGPReadMessage(r, symKey, symKeyCipher)
	if err != nil {
		return nil, err
	}
	// we get the plain key options back
	optsData, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not read PGP body")
	}
	return commonDecryptLayer(encLayer, optsData)
}

// encodeWrappedKeys encodes wrapped openpgp keys to a string readable ','
// separated base64 strings. The last item is the encrypted body
func (le *pgpLayerEncryptor) encodeWrappedKeys(keys [][]byte, pgpTail []byte) string {
	var keyArray []string

	for _, k := range keys {
		keyArray = append(keyArray, base64.StdEncoding.EncodeToString(k))
	}
	keyArray = append(keyArray, base64.StdEncoding.EncodeToString(pgpTail))

	return strings.Join(keyArray, ",")
}

// decodeWrappedKeys decodes wrapped openpgp keys from string readable ','
// separated base64 strings to their byte values; the last item in the
// list is the encrypted body
func (le *pgpLayerEncryptor) decodeWrappedKeys(keys string) ([][]byte, []byte, error) {
	if keys == "" {
		return nil, nil, nil
	}
	keySplit := strings.Split(keys, ",")

	// last item is the encrypted data block; remove it from keySplit
	pgpTail, err := base64.StdEncoding.DecodeString(keySplit[len(keySplit) - 1])
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not base64 decode pgpTail")
	}
	keySplit = keySplit[:len(keySplit) - 1]

	keyBytes := make([][]byte, 0, len(keySplit))

	for _, v := range keySplit {
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, nil, err
		}
		keyBytes = append(keyBytes, data)
	}

	return keyBytes, pgpTail, nil
}

// GetKeyIdsFromWrappedKeys converts the wrappedKeys to uint64 keyIds
func (le *pgpLayerEncryptor) GetKeyIdsFromWrappedKeys(wrappedKeys string) ([]uint64, [][]byte, error) {
	keys, _, err := le.decodeWrappedKeys(wrappedKeys)
	if err != nil {
		return nil, nil, err
	}
	keyIds, err := PGPWrappedKeysToKeyIds(keys)
	if err != nil {
		return nil, nil, err
	}
	return keyIds, keys, err
}

// GetRecipients converts the wrappedKeys to an array of recipients
func (le *pgpLayerEncryptor) GetRecipients(wrappedKeys string) ([]string, error) {
	keyIds , _, err := le.GetKeyIdsFromWrappedKeys(wrappedKeys)
	if err != nil {
		return nil, err
	}
	var array []string
	for _, keyid := range keyIds {
		array = append(array, "0x"+strconv.FormatUint(keyid, 16))
	}
	return array, nil
}

func (le *pgpLayerEncryptor) GetAnnotationID() string {
	return "org.opencontainers.image.pgp.keys"
}

// GetPrivateKey walks the list of layerInfos and tries to decrypt the
// wrapped symmetric keys. For this it determines whether a private key is
// in the GPGVault or on this system and prompts for the passwords for those
// that are available. If we do not find a private key on the system for
// getting to the symmetric key of a layer then an error is generated.
// Otherwise the wrapped symmetric key is test-decrypted using the private key.
func GetPrivateKey(layerInfos []LayerInfo, gpgClient GPGClient, gpgVault GPGVault) (map[string]string, error) {
	// PrivateKeyData describes a private key
	type PrivateKeyData struct {
		KeyData         []byte
		KeyDataPassword []byte
		KeyID           uint64
	}
	var pkd PrivateKeyData
	parameters := make(map[string]string)
	keyIDPasswordMap := make(map[uint64]PrivateKeyData)

	encryptor := GetEncryptor("pgp")

	// we need to decrypt one symmetric key per encrypted layer per platform
	for _, layerInfo := range layerInfos {
		keyIds, keys, err := encryptor.GetKeyIdsFromWrappedKeys(layerInfo.WrappedKeys)
		if err != nil {
			return parameters, err
		}

		found := false
		for _, keyid := range keyIds {
			// do we have this key? -- first check the vault
			if gpgVault != nil {
				_, keydata := gpgVault.GetGPGPrivateKey(keyid)
				if len(keydata) > 0 {
					pkd = PrivateKeyData{
						KeyData:         keydata,
						KeyDataPassword: nil, // password not supported in this case
						KeyID:           keyid,
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
						return parameters, err
					}
					keydata, err := gpgClient.GetGPGPrivateKey(keyid, string(password))
					if err != nil {
						return parameters, err
					}
					pkd = PrivateKeyData{
						KeyData:         keydata,
						KeyDataPassword: password,
						KeyID:           keyid,
					}
					keyIDPasswordMap[keyid] = pkd
				}
			} else {
				return parameters, errors.Wrapf(errdefs.ErrInvalidArgument, "No GPGVault or GPGClient passed.")
			}

			// test the password by trying a decryption
			_, _, err := PGPDecryptSymmetricKey(keys, keyid, pkd.KeyData, pkd.KeyDataPassword, nil)
			if err != nil {
				return parameters, err
			}

			found = true
			break
		}
		if !found && len(layerInfo.WrappedKeys) > 0 {
			keyIds, _ := PGPWrappedKeysToKeyIds(keys)
			ids := Uint64ToStringArray("0x%x", keyIds)

			return parameters, errors.Wrapf(errdefs.ErrNotFound, "Missing key for decryption of layer %d of %s. Need one of the following keys: %s", layerInfo.ID, layerInfo.Platform, strings.Join(ids, ", "))
		}
	}

	parameters["gpg-privatekey"] = base64.StdEncoding.EncodeToString(pkd.KeyData)
	parameters["gpg-privatekey-password"] = base64.StdEncoding.EncodeToString(pkd.KeyDataPassword)
	parameters["gpg-privatekey-keyid"] = fmt.Sprintf("0x%x", pkd.KeyID)

	return parameters, nil
}

func (le *pgpLayerEncryptor) getSymKeyParameters(dcparameters map[string]string, keys [][]byte) ([]byte, packet.CipherFunction, error) {
	var keyid uint64

	_, err := fmt.Sscanf(dcparameters["gpg-privatekey-keyid"], "0x%x", &keyid)
	if err != nil {
		return nil, packet.CipherFunction(0), errors.Wrapf(err, "Could not Sscan %s as hex number\n", dcparameters["gpg-privatekey-keyid"])
	}
	gpgPrivateKey, err := base64.StdEncoding.DecodeString(dcparameters["gpg-privatekey"])
	if err != nil {
		return nil, packet.CipherFunction(0), errors.Wrapf(err, "Could not base64 decode gpg-privatekey\n")
	}
	gpgPrivateKeyPwd, err := base64.StdEncoding.DecodeString(dcparameters["gpg-privatekey-password"])
	if err != nil {
		return nil, packet.CipherFunction(0), errors.Wrapf(err, "Could not base64 decode gpg-privatekey-password\n")
	}
	return PGPDecryptSymmetricKey(keys, keyid, gpgPrivateKey, gpgPrivateKeyPwd, nil)
}

