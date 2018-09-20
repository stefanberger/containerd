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
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/mail"
	"os"
	"strconv"
	"strings"

	"github.com/containerd/containerd/errdefs"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

type gpgKeyWrapper struct {
}

var (
	// GPGDefaultEncryptConfig is the default configuration for layer encryption/decryption
	GPGDefaultEncryptConfig = &packet.Config{
		Rand:              rand.Reader,
		DefaultHash:       crypto.SHA256,
		DefaultCipher:     packet.CipherAES256,
		CompressionConfig: &packet.CompressionConfig{Level: 0}, // No compression
		RSABits:           2048,
	}
)

func (kw *gpgKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.pgp"
}

// WrapKeys wraps the session key for recpients and encrypts the optsData, which
// describe the symmetric key used for encrypting the layer
func (kw *gpgKeyWrapper) WrapKeys(ec *EncryptConfig, optsData []byte) ([]byte, error) {
	ciphertext := new(bytes.Buffer)
	el, err := kw.createEntityList(ec)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create entity list")
	}
	if len(el) == 0 {
		// nothing to do -- not an error
		return nil, nil
	}

	plaintextWriter, err := openpgp.Encrypt(ciphertext,
		el,  /*EntityList*/
		nil, /* Sign*/
		nil, /* FileHint */
		GPGDefaultEncryptConfig)
	if err != nil {
		return nil, err
	}

	if _, err = plaintextWriter.Write(optsData); err != nil {
		return nil, err
	} else if err = plaintextWriter.Close(); err != nil {
		return nil, err
	}
	return ciphertext.Bytes(), err
}

// UnwrapKey unwraps the symmetric key with which the layer is encrypted
// This symmetric key is encrypted in the PGP payload.
func (kw *gpgKeyWrapper) UnwrapKey(dc *DecryptConfig, pgpPacket []byte) ([]byte, error) {
	b64pgpPrivateKeys, b64pgpPrivateKeysPwd, err := kw.getKeyParameters(dc.Parameters)
	if err != nil {
		return nil, err
	}

	b64pgpPrivateKeysPwdArray := strings.Split(b64pgpPrivateKeysPwd, ",")

	for idx, b64pgpPrivateKey := range strings.Split(b64pgpPrivateKeys, ",") {
		pgpPrivateKey, err := base64.StdEncoding.DecodeString(b64pgpPrivateKey)
		if err != nil {
			return nil, errors.Wrap(err, "Could not base64 decode PGP private key")
		}
		r := bytes.NewBuffer(pgpPrivateKey)
		entityList, err := openpgp.ReadKeyRing(r)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to parse private keys")
		}

		var prompt openpgp.PromptFunction
		if len(b64pgpPrivateKeysPwdArray) > idx {
			prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
				return base64.StdEncoding.DecodeString(b64pgpPrivateKeysPwdArray[idx])
			}
		}

		r = bytes.NewBuffer(pgpPacket)
		md, err := openpgp.ReadMessage(r, entityList, prompt, GPGDefaultEncryptConfig)
		if err != nil {
			continue
		}
		// we get the plain key options back
		optsData, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			continue
		}
		return optsData, nil
	}
	return nil, errors.New("PGP: No suitable key found to unwrap key")
}

// GetKeyIdsFromWrappedKeys converts the base64 encoded PGPPacket to uint64 keyIds
func (kw *gpgKeyWrapper) GetKeyIdsFromPacket(b64pgpPackets string) ([]uint64, error) {

	var keyids []uint64
	for _, b64pgpPacket := range strings.Split(b64pgpPackets, ",") {
		pgpPacket, err := base64.StdEncoding.DecodeString(b64pgpPacket)
		if err != nil {
			return nil, errors.Wrapf(err, "Could not decode base64 encoded PGP packet")
		}
		newids, err := kw.getKeyIDs(pgpPacket)
		if err != nil {
			return nil, err
		}
		keyids = append(keyids, newids...)
	}
	return keyids, nil
}

// getKeyIDs parses a PGPPacket and gets the list of recipients' key IDs
func (kw *gpgKeyWrapper) getKeyIDs(pgpPacket []byte) ([]uint64, error) {
	var keyids []uint64

	kbuf := bytes.NewBuffer(pgpPacket)
	packets := packet.NewReader(kbuf)
ParsePackets:
	for {
		p, err := packets.Next()
		if err == io.EOF {
			break ParsePackets
		}
		if err != nil {
			return []uint64{}, errors.Wrapf(err, "packets.Next() failed")
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

// GetRecipients converts the wrappedKeys to an array of recipients
func (kw *gpgKeyWrapper) GetRecipients(b64pgpPackets string) ([]string, error) {
	keyIds, err := kw.GetKeyIdsFromPacket(b64pgpPackets)
	if err != nil {
		return nil, err
	}
	var array []string
	for _, keyid := range keyIds {
		array = append(array, "0x"+strconv.FormatUint(keyid, 16))
	}
	return array, nil
}

func (kw *gpgKeyWrapper) getKeyParameters(dcparameters map[string]string) (string, string, error) {

	if dcparameters["gpg-privatekeys"] == "" {
		return "", "", errors.New("GPG: Missing private key parameter")
	}

	return dcparameters["gpg-privatekeys"], dcparameters["gpg-privatekeys-password"], nil
}

// createEntityList creates the opengpg EntityList by reading the KeyRing
// first and then filtering out recipients' keys
func (kw *gpgKeyWrapper) createEntityList(ec *EncryptConfig) (openpgp.EntityList, error) {
	pgpPubringfile, err := base64.StdEncoding.DecodeString(ec.Parameters["gpg-pubkeyringfile"])
	if err != nil {
		return nil, errors.Wrapf(err, "")
	}
	r := bytes.NewReader(pgpPubringfile)

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

// GPGGetPrivateKey walks the list of layerInfos and tries to decrypt the
// wrapped symmetric keys. For this it determines whether a private key is
// in the GPGVault or on this system and prompts for the passwords for those
// that are available. If we do not find a private key on the system for
// getting to the symmetric key of a layer then an error is generated.
// Otherwise the wrapped symmetric key is test-decrypted using the private key.
func GPGGetPrivateKey(layerInfos []LayerInfo, gpgClient GPGClient, gpgVault GPGVault, mustFindKey bool) (map[string]string, error) {
	// PrivateKeyData describes a private key
	type PrivateKeyData struct {
		KeyData         []byte
		KeyDataPassword []byte
	}
	var pkd PrivateKeyData
	parameters := make(map[string]string)
	keyIDPasswordMap := make(map[uint64]PrivateKeyData)

	for _, layerInfo := range layerInfos {
		for scheme, b64pgpPackets := range layerInfo.WrappedKeysMap {
			if scheme != "pgp" {
				continue
			}
			encryptor := GetKeyWrapper(scheme)
			if encryptor == nil {
				return parameters, errors.Errorf("Could not get KeyWrapper for %s\n", scheme)
			}
			keyIds, err := encryptor.GetKeyIdsFromPacket(b64pgpPackets)
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
						}
						keyIDPasswordMap[keyid] = pkd
						found = true
						break
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
					if _, ok = keyIDPasswordMap[keyid]; !ok {
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
						}
						keyIDPasswordMap[keyid] = pkd
						found = true
						break
					}
				} else {
					return parameters, errors.Wrapf(errdefs.ErrInvalidArgument, "No GPGVault or GPGClient passed.")
				}

				// FIXME: test the password by trying a decryption
				//_, _, err := PGPDecryptSymmetricKey(keys, keyid, pkd.KeyData, pkd.KeyDataPassword, nil)
				//if err != nil {
				//	return parameters, err
				//}
			}
			if !found && len(b64pgpPackets) > 0 && mustFindKey {
				ids := Uint64ToStringArray("0x%x", keyIds)

				return parameters, errors.Wrapf(errdefs.ErrNotFound, "Missing key for decryption of layer %d of %s. Need one of the following keys: %s", layerInfo.ID, layerInfo.Platform, strings.Join(ids, ", "))
			}
		}
	}

	var (
		privKeys    []string
		privKeysPwd []string
	)
	for _, pkd := range keyIDPasswordMap {
		privKeys = append(privKeys, base64.StdEncoding.EncodeToString(pkd.KeyData))
		privKeysPwd = append(privKeysPwd, base64.StdEncoding.EncodeToString(pkd.KeyDataPassword))
	}
	parameters["gpg-privatekeys"] = strings.Join(privKeys, ",")
	parameters["gpg-privatekeys-password"] = strings.Join(privKeysPwd, ",")

	return parameters, nil
}
