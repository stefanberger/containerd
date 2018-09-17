package encryption

import (
	"github.com/pkg/errors"
)

// LayerCipherType is the ciphertype as specified in the layer metadata
type LayerCipherType string

// TODO: Should be obtained from OCI spec once included
const (
	AeadAes128Gcm LayerCipherType = "AEAD_AES_128_GCM"
	AeadAes256Gcm LayerCipherType = "AEAD_AES_256_GCM"
)

// LayerBlockCipherOptions includes the information required to encrypt/decrypt
// an image
type LayerBlockCipherOptions struct {
	SymmetricKey  []byte            `json:'symkey'`
	CipherOptions map[string]string `json:'cipheroptions'`
}

// LayerblockCipher returns a provider for encrypt/decrypt functionality
// for handling the layer data for a specific algorithm
type LayerBlockCipher interface {
	// Encrypt takes in layer data and returns the ciphertext and relevant LayerBlockCipherOptions
	Encrypt(layerData []byte, opt LayerBlockCipherOptions) ([]byte, LayerBlockCipherOptions, error)
	// Decrypt takes in layer ciphertext data and returns the plaintext and relevant LayerBlockCipherOptions
	Decrypt(layerData []byte, opt LayerBlockCipherOptions) ([]byte, LayerBlockCipherOptions, error)
}

// LayerBlockCipherHandler is the handler for encrypt/decrypt for layers
type LayerBlockCipherHandler struct {
	cipherMap map[LayerCipherType]LayerBlockCipher
}

// Encrypt is the handler for the layer decrpytion routine
func (h *LayerBlockCipherHandler) Encrypt(layerData []byte, typ LayerCipherType, opt LayerBlockCipherOptions) ([]byte, LayerBlockCipherOptions, error) {
	if c, ok := h.cipherMap[typ]; ok {
		return c.Encrypt(layerData, opt)
	}
	return nil, LayerBlockCipherOptions{}, errors.New("Not supported Cipher Type")
}

// Decrypt is the handler for the layer decrpytion routine
func (h *LayerBlockCipherHandler) Decrypt(layerData []byte, typ LayerCipherType, opt LayerBlockCipherOptions) ([]byte, LayerBlockCipherOptions, error) {
	if c, ok := h.cipherMap[typ]; ok {
		return c.Decrypt(layerData, opt)
	}
	return nil, LayerBlockCipherOptions{}, errors.New("Not supported Cipher Type")
}

// NewLayerBlockCipherHandler returns a new default handler
func NewLayerBlockCipherHandler() (*LayerBlockCipherHandler, error) {
	h := LayerBlockCipherHandler{
		cipherMap: map[LayerCipherType]LayerBlockCipher{},
	}

	var err error
	h.cipherMap[AeadAes128Gcm], err = NewGCMLayerBlockCipher(128)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to set up Cipher GCM 128")
	}

	h.cipherMap[AeadAes256Gcm], err = NewGCMLayerBlockCipher(256)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to set up Cipher GCM 256")
	}

	return &h, nil
}
