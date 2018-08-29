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

/*
   Some parts of this file were copied from golang's openpgp implementation
   which is under the following license:

   Copyright (c) 2009 The Go Authors. All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:

      * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above
   copyright notice, this list of conditions and the following disclaimer
   in the documentation and/or other materials provided with the
   distribution.
      * Neither the name of Google Inc. nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package images

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"crypto"
	"crypto/rand"

	"github.com/containerd/containerd/errdefs"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var (
	// DefaultEncryptConfig is the default configuration for layer encryption/decryption
	DefaultEncryptConfig = &packet.Config{
		Rand:              rand.Reader,
		DefaultHash:       crypto.SHA256,
		DefaultCipher:     packet.CipherAES128,
		CompressionConfig: &packet.CompressionConfig{Level: 0}, // No compression
		RSABits:           2048,
	}
)

// encryptData encrypts data with openpgp and returns the encrypted blob and wrapped keys separately
func encryptData(data []byte, recipients openpgp.EntityList, symKey []byte) (encBlob []byte, wrappedKeys [][]byte, err error) {
	config := DefaultEncryptConfig

	// If no symkey, generate
	if len(symKey) == 0 {
		symKey = make([]byte, config.DefaultCipher.KeySize())
		if _, err := io.ReadFull(config.Random(), symKey); err != nil {
			return nil, nil, err
		}
	}

	wrappedKeys, err = createWrappedKeys(symKey, recipients, config)
	if err != nil {
		return nil, nil, err
	}

	encBlob, err = createEncryptedBlob(data, symKey, config)
	if err != nil {
		return nil, nil, err
	}

	return encBlob, wrappedKeys, nil
}

// createWrappedKeys creates wrapped key bytes
func createWrappedKeys(symKey []byte, recipients openpgp.EntityList, config *packet.Config) (wrappedKeys [][]byte, err error) {
	return addRecipientsToKeys([][]byte{}, recipients, symKey, config.DefaultCipher, config)
}

// addRecipientsToKeys adds wrapped keys to an existing list of wrapped keys by
// encrypting the given symmetric key (symKey) with a public key of each one
// of the recipients
func addRecipientsToKeys(keys [][]byte, recipients openpgp.EntityList, symKey []byte, symKeyCipher packet.CipherFunction, config *packet.Config) ([][]byte, error) {
	keyIds, err := WrappedKeysToKeyIds(keys)
	if err != nil {
		return nil, err
	}

	encKeys := keys

	for _, et := range recipients {
		pkey, canEncrypt := encryptionKey(et, time.Now())
		if !canEncrypt {
			return nil, errors.Wrapf(errdefs.ErrInvalidArgument, "key doesn't support encryption")
		}
		// already part of the wrapped keys ?
		found := false
		for _, v := range keyIds {
			if v == pkey.PublicKey.KeyId {
				found = true
				break
			}
		}
		if !found {
			encKeyBuf := new(bytes.Buffer)
			if err := packet.SerializeEncryptedKey(encKeyBuf, pkey.PublicKey, symKeyCipher, symKey, config); err != nil {
				return nil, errors.Wrapf(err, "Error serializing encrypted key: %v", err)
			}
			encKeys = append(encKeys, encKeyBuf.Bytes())
			keyIds = append(keyIds, pkey.PublicKey.KeyId)
		}
	}
	return encKeys, nil
}

func removeRecipientsFromKeys(keys [][]byte, removeRecipients openpgp.EntityList) ([][]byte, error) {
	var wrappedKeys [][]byte

	for _, ek := range keys {
		ekbuf := bytes.NewBuffer(ek)
		p, err := packet.Read(ekbuf)
		if err != nil {
			return [][]byte{}, errors.Wrapf(errdefs.ErrInvalidArgument, "Err reading enc key packet: %v", err)
		}
		pek := p.(*packet.EncryptedKey)

		if len(removeRecipients.KeysById(pek.KeyId)) == 0 {
			// we can keep this key
			wrappedKeys = append(wrappedKeys, ek)
		}
	}

	return wrappedKeys, nil
}

// createEncryptedBlob creates encrypted data blob bytes
func createEncryptedBlob(data []byte, symKey []byte, config *packet.Config) (encBlob []byte, err error) {
	// Perform encryption
	encData := new(bytes.Buffer)
	encContent, err := packet.SerializeSymmetricallyEncrypted(encData, config.DefaultCipher, symKey, config)
	if err != nil {
		return nil, fmt.Errorf("Error serializing SymmetricallyEncrypted packet: %v", err)
	}

	content, err := packet.SerializeLiteral(encContent, true, "", 0)
	if err != nil {
		return nil, fmt.Errorf("Error serializing Lietral packet: %v", err)
	}

	if _, err := content.Write(data); err != nil {
		return nil, err
	}

	if err := content.Close(); err != nil {
		return nil, err
	}

	encBlob = encData.Bytes()

	return encBlob, nil
}

// Helper private functions copied from golang.org/x/crypto/openpgp/packet

// encryptionKey returns the best candidate Key for encrypting a message to the
// given Entity.
func encryptionKey(e *openpgp.Entity, now time.Time) (openpgp.Key, bool) {
	candidateSubkey := -1

	// Iterate the keys to find the newest key
	var maxTime time.Time
	for i, subkey := range e.Subkeys {
		if subkey.Sig.FlagsValid &&
			subkey.Sig.FlagEncryptCommunications &&
			subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
			!subkey.Sig.KeyExpired(now) &&
			(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
			candidateSubkey = i
			maxTime = subkey.Sig.CreationTime
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return openpgp.Key{e, subkey.PublicKey, subkey.PrivateKey, subkey.Sig}, true
	}

	// If we don't have any candidate subkeys for encryption and
	// the primary key doesn't have any usage metadata then we
	// assume that the primary key is ok. Or, if the primary key is
	// marked as ok to encrypt to, then we can obviously use it.
	i := primaryIdentity(e)
	if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagEncryptCommunications &&
		e.PrimaryKey.PubKeyAlgo.CanEncrypt() &&
		!i.SelfSignature.KeyExpired(now) {
		return openpgp.Key{e, e.PrimaryKey, e.PrivateKey, i.SelfSignature}, true
	}

	// This Entity appears to be signing only.
	return openpgp.Key{}, false
}

// primaryIdentity returns the Identity marked as primary or the first identity
// if none are so marked.
func primaryIdentity(e *openpgp.Entity) *openpgp.Identity {
	var firstIdentity *openpgp.Identity
	for _, ident := range e.Identities {
		if firstIdentity == nil {
			firstIdentity = ident
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident
		}
	}
	return firstIdentity
}

// WrappedKeysToKeyIds converts an array of wrapped keys into an array of
// their key Ids
func WrappedKeysToKeyIds(keys [][]byte) ([]uint64, error) {
	var keyids []uint64

	kbytes := make([]byte, 0)
	for _, k := range keys {
		kbytes = append(kbytes, k...)
	}
	kbuf := bytes.NewBuffer(kbytes)

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
		}
	}
	return keyids, nil
}

// DecryptSymmetricKey decrypts a symmetric key from an array of wrapped keys. The private
// key with the given keyid is retrieved from the keyData byte array and decrypted using
// the given keyDataPassword; the private key is then used to decrypt the wrapped symmetric
// key
func DecryptSymmetricKey(keys [][]byte, keyid uint64, keyData []byte, keyDataPassword []byte, config *packet.Config) ([]byte, packet.CipherFunction, error) {
	kbytes := make([]byte, 0)
	for _, k := range keys {
		kbytes = append(kbytes, k...)
	}
	kbuf := bytes.NewBuffer(kbytes)

	var ek *packet.EncryptedKey

	packets := packet.NewReader(kbuf)
ParsePackets:
	for {
		p, err := packets.Next()
		if err == io.EOF {
			break ParsePackets
		}
		if err != nil {
			return []byte{}, 0, errors.Wrapf(err, "packets.Next() failed")
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			if p.KeyId == keyid {
				ek = p
				break ParsePackets
			}
		}
	}

	if ek == nil {
		return []byte{}, 0, errors.Wrapf(errdefs.ErrNotFound, "Key with id 0x%x could not be found.", keyid)
	}

	// read the private keys
	r := bytes.NewReader(keyData)
	entityList, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return []byte{}, 0, errors.Wrapf(err, "Could not read keyring")
	}
	// decrypt them
	decKeys := entityList.KeysByIdUsage(ek.KeyId, packet.KeyFlagEncryptCommunications)
	decrypted := false
	for _, k := range decKeys {
		if k.PrivateKey.Encrypted {
			if err := k.PrivateKey.Decrypt(keyDataPassword); err != nil {
				return []byte{}, 0, errors.Wrapf(err, "passphrase invalid for private key")
			}
		}
		err = ek.Decrypt(k.PrivateKey, config)
		if err == nil {
			decrypted = true
			break
		}
	}

	if !decrypted {
		return []byte{}, 0, errors.New("could not successfully decrypt symmetric key, no valid keys usable")
	}

	return ek.Key, ek.CipherFunc, nil
}

// ReadMessage reads an OpenPGP byte stream and decrypts the SymmetricallyEncrypted
// part with the given symmetric key and cipher
func ReadMessage(r io.Reader, symKey []byte, symKeyCipher packet.CipherFunction) (*openpgp.MessageDetails, error) {
	var se *packet.SymmetricallyEncrypted

	packets := packet.NewReader(r)

ParsePackets:
	for {
		p, err := packets.Next()
		if err == io.EOF {
			break ParsePackets
		}
		if err != nil {
			return nil, errors.Wrapf(err, "packets.Next() failed")
		}
		switch p := p.(type) {
		case *packet.SymmetricallyEncrypted:
			se = p
			break ParsePackets
		}
	}

	if se == nil {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "No symmetrically encrypted data found.")
	}

	decrypted, err := se.Decrypt(symKeyCipher, symKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Decrypting layer with symmetric key failed")
	}

	if err := packets.Push(decrypted); err != nil {
		return nil, errors.Wrapf(err, "Pushing failed")
	}

	md := new(openpgp.MessageDetails)
	var p packet.Packet
FindLiteralData:
	for {
		p, err = packets.Next()
		if err == io.EOF {
			break FindLiteralData
		}
		if err != nil {
			return nil, errors.Wrapf(err, "packets.Next() failed")
		}
		switch p := p.(type) {
		case *packet.LiteralData:
			md.LiteralData = p
			break FindLiteralData
		}
	}

	if md.LiteralData == nil {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "LiteralData not found")
	}

	md.UnverifiedBody = checkReader{md}

	return md, nil
}

type checkReader struct {
	md *openpgp.MessageDetails
}

func (cr checkReader) Read(buf []byte) (n int, err error) {
	return cr.md.LiteralData.Body.Read(buf)
}
