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

package images

import (
	"bytes"
	"io/ioutil"
	"net/mail"
	"strings"

	"github.com/containerd/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// EncryptConfig is the container image PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type EncryptConfig struct {
	Recipients     []string
	GPGPubRingFile []byte
	Operation      int32
	// for adding recipients on an already encrypted image we need the
	// private keys for the layers to get to the symmetric key so we can
	// (re)wrap it with the recpient's public key
	Dc DecryptConfig
}

const (
	OPERATION_ADD_RECIPIENTS    = int32(iota)
	OPERATION_REMOVE_RECIPIENTS = int32(iota)
)

// DecryptKeyData stores private key data for decryption and the necessary password
// for being able to access/decrypt the private key data
type DecryptKeyData struct {
	KeyData         []byte
	KeyDataPassword []byte
}

// DecryptConfig stores the KeyIDs of keys needed for decryption as keys of
// a map and the actual private key data in the values
type DecryptConfig struct {
	KeyIdMap map[uint64]DecryptKeyData
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

// HandleEncrypt encrypts a byte array using data from the EncryptConfig and also manages
// the list of recipients' keys
func HandleEncrypt(ec *EncryptConfig, data []byte, keys [][]byte) ([]byte, [][]byte, error) {
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
	case OPERATION_ADD_RECIPIENTS:
		if len(keys) > 0 {
			wrappedKeys, err = addRecipientsToKeys(keys, filteredList, ec.Dc.KeyIdMap)
		} else {
			encBlob, wrappedKeys, err = encryptData(data, filteredList, nil)
		}
	case OPERATION_REMOVE_RECIPIENTS:
		wrappedKeys, err = removeRecipientsFromKeys(keys, filteredList)
		// encBlob stays empty to indicate it wasn't touched
	}

	if err != nil {
		return nil, nil, err
	}

	return encBlob, wrappedKeys, nil
}

// Decrypt decrypts a byte array using data from the DecryptConfig
func Decrypt(dc *DecryptConfig, encBody []byte, desc ocispec.Descriptor) ([]byte, error) {
	keyIds, err := GetKeyIds(desc)
	if err != nil {
		return nil, err
	}

	keys, err := getWrappedKeys(desc)
	if err != nil {
		return nil, err
	}

	data := assembleEncryptedMessage(encBody, keys)
	// decrypt with the right key
	for _, keyId := range keyIds {
		if keydata, ok := dc.KeyIdMap[keyId]; ok {
			r := bytes.NewReader(keydata.KeyData)
			entityList, err := openpgp.ReadKeyRing(r)
			if err != nil {
				return []byte{}, err
			}
			entity := entityList[0]
			entity.PrivateKey.Decrypt(keydata.KeyDataPassword)
			for _, subkey := range entity.Subkeys {
				subkey.PrivateKey.Decrypt(keydata.KeyDataPassword)
			}
			md, err := openpgp.ReadMessage(bytes.NewBuffer(data), entityList, nil, nil)
			if err != nil {
				return []byte{}, err
			}
			return ioutil.ReadAll(md.UnverifiedBody)
		}
	}
	return []byte{}, errors.Wrapf(errdefs.ErrNotFound, "No suitable decryption key was found.")
}

// GetKeyIds gets the Key IDs for which the data are encrypted
func GetKeyIds(desc ocispec.Descriptor) ([]uint64, error) {
	var keyids []uint64

	keys, err := getWrappedKeys(desc)
	if err != nil {
		return nil, err
	}

	kbytes := make([]byte, 0)
	for _, k := range keys {
		kbytes = append(kbytes, k...)
	}
	kbuf := bytes.NewBuffer(kbytes)

	packets := packet.NewReader(kbuf)
ParsePackets:
	for {
		p, err := packets.Next()
		if err != nil {
			break ParsePackets
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			keyids = append(keyids, p.KeyId)
		case *packet.SymmetricallyEncrypted:
			break ParsePackets
		}
	}
	return keyids, nil
}
