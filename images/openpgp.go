package images

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

func addRecipientsToKeys(keys [][]byte, newRecipients openpgp.EntityList, keyIdMap map[uint64]DecryptKeyData) ([][]byte, error) {
	return [][]byte{}, errors.Wrapf(errdefs.ErrNotImplemented, "Adding recipients is not supported\n")
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

// decryptData decrypts an openpgp encrypted blob and wrapped keys and returns the decrypted data
func decryptData(encBlob []byte, wrappedKeys [][]byte, kring openpgp.EntityList) (data []byte, err error) {
	// Assemble message by concatenating packets
	message := make([]byte, 0)
	for _, ek := range wrappedKeys {
		message = append(message, ek...)

		// experiment
		ekbuf := bytes.NewBuffer(ek)
		p, err := packet.Read(ekbuf)
		if err != nil {
			log.Fatalf("Err reading enc key packet: %v", err)
		}

		pek := p.(*packet.EncryptedKey)
		log.Printf("Enckey KeyID: %x", pek.KeyId)
		log.Printf("  getting KeyID: %v", kring.KeysById(pek.KeyId))

	}

	message = append(message, encBlob...)

	log.Printf("Encrypted message bytes: %x", message)

	promptFunc := func(key []openpgp.Key, symm bool) ([]byte, error) {
		for _, k := range key {
			if symm {
				return nil, errors.Wrapf(errdefs.ErrNotImplemented, "Not handled")
			} else {
				k.PrivateKey.Decrypt([]byte("hidden!"))
			}
		}
		return nil, nil
	}
	messageIn := bytes.NewBuffer(message)
	md, err := openpgp.ReadMessage(messageIn, kring, promptFunc, DefaultEncryptConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to read message: %v", err)
	}

	plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading encrypted contents: %s", err)
	}

	return plaintext, nil
}

// createWrappedKeys creates wrapped key bytes
func createWrappedKeys(symKey []byte, recipients openpgp.EntityList, config *packet.Config) (wrappedKeys [][]byte, err error) {
	// Array of serialized EncryptedKeys
	encKeys := make([][]byte, 0, len(recipients))
	encKeyBuf := new(bytes.Buffer)

	for _, et := range recipients {
		pkey, canEncrypt := encryptionKey(et, time.Now())
		if !canEncrypt {
			log.Printf("Error key doesn't support encryption")
			return nil, fmt.Errorf("key doesn't support encryption")
		}
		if err := packet.SerializeEncryptedKey(encKeyBuf, pkey.PublicKey, config.DefaultCipher, symKey, config); err != nil {
			return nil, fmt.Errorf("Error serializing encrypted key: %v", err)
		}
		encryptedKeyBytes := encKeyBuf.Bytes()
		encKeys = append(encKeys, encryptedKeyBytes)
		encKeyBuf = new(bytes.Buffer)
	}

	log.Printf("Encrypted keys' bytes: %x", encKeys)

	return encKeys, nil
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
	log.Printf("Encrypted data bytes: %x", encBlob)

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

// signingKey return the best candidate Key for signing a message with this
// Entity.
func signingKey(e *openpgp.Entity, now time.Time) (openpgp.Key, bool) {
	candidateSubkey := -1

	for i, subkey := range e.Subkeys {
		if subkey.Sig.FlagsValid &&
			subkey.Sig.FlagSign &&
			subkey.PublicKey.PubKeyAlgo.CanSign() &&
			!subkey.Sig.KeyExpired(now) {
			candidateSubkey = i
			break
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return openpgp.Key{e, subkey.PublicKey, subkey.PrivateKey, subkey.Sig}, true
	}

	// If we have no candidate subkey then we assume that it's ok to sign
	// with the primary key.
	i := primaryIdentity(e)
	if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagSign &&
		!i.SelfSignature.KeyExpired(now) {
		return openpgp.Key{e, e.PrimaryKey, e.PrivateKey, i.SelfSignature}, true
	}

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
