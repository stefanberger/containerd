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
	"encoding/base64"
	"strings"

	"github.com/pkg/errors"

	jose "gopkg.in/square/go-jose.v2"
)

type jweKeyWrapper struct {
}

func (kw *jweKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.jwe"
}

// WrapKeys wraps the session key for recpients and encrypts the optsData, which
// describe the symmetric key used for encrypting the layer
func (kw *jweKeyWrapper) WrapKeys(ec *EncryptConfig, optsData []byte) ([]byte, error) {
	var joseRecipients []jose.Recipient

	err := addPubKeys(&joseRecipients, ec.Parameters["pubkeys"])
	if err != nil {
		return nil, err
	}
	// no recipients is not an error...
	if len(joseRecipients) == 0 {
		return nil, nil
	}

	encrypter, err := jose.NewMultiEncrypter(jose.A256GCM, joseRecipients, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "jose.NewMultiEncrypter failed")
	}
	jwe, err := encrypter.Encrypt(optsData)
	if err != nil {
		return nil, errors.Wrapf(err, "JWE Encrypt failed")
	}
	return []byte(jwe.FullSerialize()), nil
}

func (kw *jweKeyWrapper) UnwrapKey(dc *DecryptConfig, jweString []byte) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(string(jweString))
	if err != nil {
		return nil, errors.New("jose.ParseEncrypted failed")
	}

	privKeys := kw.GetPrivateKeys(dc.Parameters)
	if privKeys == "" {
		return nil, errors.New("No private keys found for JWE decryption")
	}

	for _, b64PrivKey := range strings.Split(privKeys, ",") {
		privKey, err := base64.StdEncoding.DecodeString(b64PrivKey)
		if err != nil {
			return nil, errors.Wrapf(err, "JWE: Could not base64 decode privat key")
		}

		key, err := parsePrivateKey(privKey, "JWE")
		if err != nil {
			return nil, err
		}
		_, _, plain, err := jwe.DecryptMulti(key)
		if err == nil {
			return plain, nil
		}
	}
	return nil, errors.New("JWE: No suitable private key found for decryption")
}

func (kw *jweKeyWrapper) GetPrivateKeys(dcparameters map[string]string) string {
	return dcparameters["privkeys"]
}

func (kw *jweKeyWrapper) GetKeyIdsFromPacket(b64jwes string) ([]uint64, error) {
	return nil, nil
}

func (kw *jweKeyWrapper) GetRecipients(b64jwes string) ([]string, error) {
	return []string{"[jwe]"}, nil
}

func addPubKeys(joseRecipients *[]jose.Recipient, b64PubKeys string) error {
	if b64PubKeys == "" {
		return nil
	}
	for _, b64PubKey := range strings.Split(b64PubKeys, ",") {
		pubKey, err := base64.StdEncoding.DecodeString(b64PubKey)
		if err != nil {
			return errors.Wrapf(err, "Could not base64 decode public key")
		}

		key, err := parsePublicKey(pubKey, "JWE")
		if err != nil {
			return err
		}

		*joseRecipients = append(*joseRecipients, jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key: &jose.JSONWebKey{
				Key: key,
			},
		})
	}
	return nil
}
