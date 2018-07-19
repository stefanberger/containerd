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

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/openpgp"
)

// EncryptConfig is the container image PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type EncryptConfig struct {
       Recipients     []string
       GPGPubRingFile []byte
}

type Encryptor interface {
}

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
		for k, _ := range entity.Identities {
			fmt.Printf("k = %s\n",k)
			addr, err := mail.ParseAddress(k)
			if err != nil {
				return nil, err
			}
			for _, r := range ec.Recipients {
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

// Encrypt encrypts a byte array using data from the EncryptConfig
func Encrypt(ec *EncryptConfig, data []byte) ([]byte, error) {
	filteredList, err := createEntityList(ec)
	if err != nil {
		return nil, err
	}
	if len(filteredList) == 0 {
		return nil, fmt.Errorf("No keys were found to encrypt message to.\n")
	}

	buf := new(bytes.Buffer)

	w, err := openpgp.Encrypt(buf, filteredList, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(buf)
}

