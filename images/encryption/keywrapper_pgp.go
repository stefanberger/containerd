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
	"strconv"
	"strings"

	"github.com/containerd/containerd/errdefs"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type pgpKeyWrapper struct {
}

func (le *pgpKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.pgp.keys"
}

// WrapKeys wraps the session key for recpients and encrypts the optsData, which
// describe the symmetric key used for encrypting the layer; use the symKey as
// the session key to wrap
func (le *pgpKeyWrapper) WrapKeys(ec *EncryptConfig, encLayer []byte, wrappedKeys string, optsData []byte) ([]byte, string, error) {
	var (
		err error
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
		return encLayer, wrappedKeys, nil
	}

	switch ec.Operation {
	case OperationAddRecipients:
		if len(keys) > 0 {
			symKey, symKeyCipher, err := le.getSymKeyParameters(ec.Dc.Parameters, keys)
			if err != nil {
				return nil, "", err
			}
			keys, err = pgpAddRecipientsToKeys(keys, filteredList, symKey, symKeyCipher, nil)
			if err != nil {
				return nil, "", err
			}
		} else {
			pgpTail, keys, err = pgpEncryptData(optsData, filteredList, nil)
		}
	case OperationRemoveRecipients:
		keys, err = pgpRemoveRecipientsFromKeys(keys, filteredList)
		// encLayer stays empty to indicate it wasn't touched
	}

	if err != nil {
		return nil, "", err
	}

	wrappedKeys = le.encodeWrappedKeys(keys, pgpTail)

	return encLayer, wrappedKeys, nil
}

// UnwrapKey unwraps the symmetric key with which the layer is encrypted
// This symmetric key is encrypted in the PGP payload.
func (le *pgpKeyWrapper) UnwrapKey(dc *DecryptConfig, wrappedKeys string) ([]byte, error) {

	keys, pgpTail, err := le.decodeWrappedKeys(wrappedKeys)
	if err != nil || keys == nil {
		return nil, err
	}

	symKey, symKeyCipher, err := le.getSymKeyParameters(dc.Parameters, keys)
	if err != nil {
		return nil, err
	}

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
	return optsData, nil
}

// GetKeyIdsFromWrappedKeys converts the wrappedKeys to uint64 keyIds
func (le *pgpKeyWrapper) GetKeyIdsFromWrappedKeys(wrappedKeys string) ([]uint64, [][]byte, error) {
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
func (le *pgpKeyWrapper) GetRecipients(wrappedKeys string) ([]string, error) {
	keyIds, _, err := le.GetKeyIdsFromWrappedKeys(wrappedKeys)
	if err != nil {
		return nil, err
	}
	var array []string
	for _, keyid := range keyIds {
		array = append(array, "0x"+strconv.FormatUint(keyid, 16))
	}
	return array, nil
}

// encodeWrappedKeys encodes wrapped openpgp keys to a string readable ','
// separated base64 strings. The last item is the encrypted body
func (le *pgpKeyWrapper) encodeWrappedKeys(keys [][]byte, pgpTail []byte) string {
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
func (le *pgpKeyWrapper) decodeWrappedKeys(keys string) ([][]byte, []byte, error) {
	if keys == "" {
		return nil, nil, nil
	}
	keySplit := strings.Split(keys, ",")

	// last item is the encrypted data block; remove it from keySplit
	pgpTail, err := base64.StdEncoding.DecodeString(keySplit[len(keySplit)-1])
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not base64 decode pgpTail")
	}
	keySplit = keySplit[:len(keySplit)-1]

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

func (le *pgpKeyWrapper) getSymKeyParameters(dcparameters map[string]string, keys [][]byte) ([]byte, packet.CipherFunction, error) {
	var keyid uint64

	if dcparameters["gpg-privatekey-keyid"] == "" || dcparameters["gpg-privatekey"] == "" {
		return nil, packet.CipherFunction(0), errors.New("GPG: Missing private key parameter")
	}

	_, err := fmt.Sscanf(dcparameters["gpg-privatekey-keyid"], "0x%x", &keyid)
	if err != nil {
		return nil, packet.CipherFunction(0), errors.Wrapf(err, "Could not Sscan %s as hex number", dcparameters["gpg-privatekey-keyid"])
	}
	gpgPrivateKey, err := base64.StdEncoding.DecodeString(dcparameters["gpg-privatekey"])
	if err != nil {
		return nil, packet.CipherFunction(0), errors.Wrapf(err, "Could not base64 decode gpg-privatekey")
	}
	gpgPrivateKeyPwd, err := base64.StdEncoding.DecodeString(dcparameters["gpg-privatekey-password"])
	if err != nil {
		return nil, packet.CipherFunction(0), errors.Wrapf(err, "Could not base64 decode gpg-privatekey-password")
	}
	return PGPDecryptSymmetricKey(keys, keyid, gpgPrivateKey, gpgPrivateKeyPwd, nil)
}

// createEntityList creates the opengpg EntityList by reading the KeyRing
// first and then filtering out recipients' keys
func (le *pgpKeyWrapper) createEntityList(ec *EncryptConfig) (openpgp.EntityList, error) {
	gpgpubringfile, err := base64.StdEncoding.DecodeString(ec.Parameters["gpg-pubkeyringfile"])
	if err != nil {
		return nil, errors.Wrapf(err, "")
	}
	r := bytes.NewReader(gpgpubringfile)

	entityList, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	gpgRecipients := ec.Parameters["gpg-recipients"]
	if gpgRecipients == "" {
		return nil, nil
	}

	recipients := strings.Split(gpgRecipients, ",")
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
	buffer.WriteString("PGP: No key found for the following recipients: ")

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
func (le *pgpKeyWrapper) assembleEncryptedMessage(encBody []byte, keys [][]byte) []byte {
	encMsg := make([]byte, 0)

	for _, k := range keys {
		encMsg = append(encMsg, k...)
	}
	encMsg = append(encMsg, encBody...)

	return encMsg
}
