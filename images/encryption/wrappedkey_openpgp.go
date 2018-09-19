package encryption

import (
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"net/mail"
	"strings"

	"github.com/containerd/containerd/errdefs"
	"github.com/pkg/errors"
)

const (
	// RecipientsOpt is the option keyword for recipients
	// it is represented as the string "recipientA,recipientB,..."
	RecipientsOpt = "recipients"
	// PubKeyRingOpt is the option keyword for the GPG public keyring
	// it is the base64 encoded string of the GPG public keyring
	PubKeyRingOpt = "pubkeyring"
	// PrivKeyRingOpt is the option keyword for the GPG private keyring
	// it is the base64 encoded data of the GPG private keyring
	PrivKeyRingOpt = "privkeyring"
)

var (
	// GPGDefaultEncryptConfig is the default configuration for layer encryption/decryption
	GPGDefaultEncryptConfig = &packet.Config{
		Rand:              rand.Reader,
		DefaultHash:       crypto.SHA256,
		DefaultCipher:     packet.CipherAES128,
		CompressionConfig: &packet.CompressionConfig{Level: 0}, // No compression
		RSABits:           2048,
	}
)

type openpgpWrappedKeyService struct {
}

// openpgpEncryptConfig is the PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type openpgpEncryptConfig struct {
	Recipients     []string
	GPGPubRingFile []byte
}

// openpgpDecryptConfig is the PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type openpgpDecryptConfig struct {
	Recipients     []string
	GPGPubRingFile []byte
}

func (s *openpgpWrappedKeyService) parseOptions(opt map[string]string) (*openpgpEncryptConfig, error) {
	recipientsStr := opt[RecipientsOpt]
	gpgPubRingFileStr, ok := opt[PubKeyRingOpt]
	if !ok {
		return nil, errors.New("No public keyring provided for openpgp encryption")
	}

	gpgPubRingFile, err := base64.StdEncoding.DecodeString(gpgPubRingFileStr)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to decode gpg pubkeyring")
	}

	return &openpgpEncryptConfig{
		Recipients:     strings.Split(recipientsStr, ","),
		GPGPubRingFile: gpgPubRingFile,
	}, nil

}

// Wrap takes a key and wraps it based on the options given
func (s *openpgpWrappedKeyService) Wrap(req *WrapKeyRequest) (*WrapKeyResponse, error) {
	ec, err := s.parseOptions(req.Opt)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse encryption options")
	}

	ciphertext := new(bytes.Buffer)
	el, err := s.createEntityList(ec)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create entity list")
	}

	plaintextWriter, err := openpgp.Encrypt(ciphertext,
		el,  /*EntityList*/
		nil, /* Sign*/
		nil, /* FileHint */
		GPGDefaultEncryptConfig)
	if err != nil {
		return nil, err
	}

	if _, err = plaintextWriter.Write(req.Key); err != nil {
		return nil, err
	} else if err = plaintextWriter.Close(); err != nil {
		return nil, err
	}

	resp := &WrapKeyResponse{
		WrappedKeys: [][]byte{ciphertext.Bytes()},
	}
	return resp, nil
}

// Unwrap takes wrapped keys and wraps it based on the options given (TODO)
func (s *openpgpWrappedKeyService) Unwrap(req *UnwrapKeyRequest) (*UnwrapKeyResponse, error) {
	return nil, errors.New("Not implemented")
}

// Helper Functions

// createEntityList creates the opengpg EntityList by reading the KeyRing
// first and then filtering out recipients' keys
func (s *openpgpWrappedKeyService) createEntityList(ec *openpgpEncryptConfig) (openpgp.EntityList, error) {
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
