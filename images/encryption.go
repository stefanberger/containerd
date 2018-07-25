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
	"fmt"
        "io/ioutil"
	"net/mail"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

)

// EncryptConfig is the container image PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type EncryptConfig struct {
       Recipients     []string
       GPGPubRingFile []byte
}

// DecryptKeyData stores private key data for decryption and the necessary password
// for being able to access/decrypt the private key data
type DecryptKeyData struct {
	KeyData []byte
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

// ReadGPGPubRingFile reads the GPG public key ring file
func ReadGPGPubRingFile() ([]byte, error) {
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	pubring := fmt.Sprintf("%s/.gnupg/pubring.gpg", home)
	gpgPubRingFile, err := ioutil.ReadFile(pubring)
	if err != nil {
		return nil, fmt.Errorf("Could not read Public keyring file %s: %v", pubring, err)
	}
	return gpgPubRingFile, nil
}

// createEntityList creates the opengpg EntityList by reading the KeyRing
// first and then filtering out recipients' keys
func createEntityList(cc *CryptoConfig) (openpgp.EntityList, error) {
	r := bytes.NewReader(cc.Ec.GPGPubRingFile)

	entityList, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	rSet := make(map[string]int)
	for _, r := range cc.Ec.Recipients {
		rSet[r] = 0
	}

	var filteredList openpgp.EntityList
	for _, entity := range entityList {
		for k, _ := range entity.Identities {
			fmt.Printf("k = %s\n",k)
			addr, err := mail.ParseAddress(k)
			if err != nil {
				return nil, err
			}
			for _, r := range cc.Ec.Recipients {
				if strings.Compare(addr.Name, r) == 0 || strings.Compare(addr.Address, r) == 0 {
					fmt.Printf(" TAKING key of %s\n", k)
					filteredList = append(filteredList, entity)
					rSet[r] = rSet[r] + 1
				}
			}
		}
	}

	// make sure we found keys for all the Recipients...
	var buffer bytes.Buffer
	notFound := false;
	buffer.WriteString("No key found for the following recipients: ")

	for k, v := range rSet {
		if v == 0 {
			if notFound {
				buffer.WriteString(", ")
			}
			buffer.WriteString(k)
			notFound = true;
		}
	}

	if notFound {
		return nil, fmt.Errorf(buffer.String())
	}

	return filteredList, nil
}

// Encrypt encrypts a byte array using data from the CryptoConfig
func Encrypt(cc *CryptoConfig, data []byte) ([]byte, [][]byte, error) {
	filteredList, err := createEntityList(cc)
	if err != nil {
		return nil, nil, err
	}
	if len(filteredList) == 0 {
		return nil, nil, fmt.Errorf("No keys were found to encrypt message to.\n")
	}

	encBlob, wrappedKeys, err := encryptData(data, filteredList, nil)
	if err != nil {
		return nil, nil, err
	}

	return encBlob, wrappedKeys, nil
}

// Decrypt decrypts a byte array using data from the CryptoConfig
func Decrypt(cc *CryptoConfig, data []byte) ([]byte, error) {
	dc := cc.Dc
	keyIds, err := GetKeyIds(ocispec.Descriptor{})
	if err != nil {
		return []byte{}, err
	}
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
	return []byte{}, fmt.Errorf("No suitable decryption key was found.")
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

