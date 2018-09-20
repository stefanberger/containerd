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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// LayerInfo holds information about an image layer
type LayerInfo struct {
	// The Id of the layer starting at 0
	ID uint32
	// Map of wrapped keys from which KeyIds can be derived with scheme as keys
	WrappedKeysMap map[string]string
	// The Digest of the layer
	Digest string
	// The size of the layer file
	FileSize int64
	// The platform for which this layer is
	Platform string
}

// LayerFilter holds criteria for which layer to select
type LayerFilter struct {
	// IDs of layers to touch; may be negative number to start from topmost layer
	// empty array means 'all layers'
	Layers []int32
	// Platforms to touch; empty array means 'all platforms'
	Platforms []ocispec.Platform
}

// EncryptConfig is the container image PGP encryption configuration holding
// the identifiers of those that will be able to decrypt the container and
// the PGP public keyring file data that contains their public keys.
type EncryptConfig struct {
	// map holding 'gpg-recipients' and 'gpg-pubkeyringfile'
	Parameters map[string]string

	// for adding recipients on an already encrypted image we need the
	// symmetric keys for the layers so we can wrap them with the recpient's
	// public key
	Operation int32 // currently only OperationAddRecipients is supported, if at all
	Dc        DecryptConfig
}

const (
	// OperationAddRecipients instructs to add a recipient
	OperationAddRecipients = int32(iota)
	// OperationRemoveRecipients instructs to remove a recipient
	OperationRemoveRecipients = int32(iota)
)

// DecryptConfig stores the platform and layer number encoded in a string as a
// key to the map. The symmetric key needed for decrypting a platform specific
// layer is stored as value.
type DecryptConfig struct {
	Parameters map[string]string
}

// CryptoConfig is a common wrapper for EncryptConfig and DecrypConfig that can
// be passed through functions that share much code for encryption and decryption
type CryptoConfig struct {
	Ec *EncryptConfig
	Dc *DecryptConfig
}

// KeyWrapper is the interface used for wrapping keys using
// a specific encryption technology (pgp, jwe)
type KeyWrapper interface {
	WrapKeys(ec *EncryptConfig, optsData []byte) ([]byte, error)
	UnwrapKey(dc *DecryptConfig, annotation []byte) ([]byte, error)
	GetAnnotationID() string

	GetKeyIdsFromPacket(packet string) ([]uint64, error)
	GetRecipients(packet string) ([]string, error)
}

func init() {
	keyWrappers = make(map[string]KeyWrapper)
	keyWrapperAnnotations = make(map[string]string)
	registerKeyWrapper("pgp", &gpgKeyWrapper{})
	registerKeyWrapper("jwe", &jweKeyWrapper{})
}

var keyWrappers map[string]KeyWrapper
var keyWrapperAnnotations map[string]string

func registerKeyWrapper(scheme string, iface KeyWrapper) {
	keyWrappers[scheme] = iface
	keyWrapperAnnotations[iface.GetAnnotationID()] = scheme
}

// GetKeyWrapper looks up the encryptor interface given an encryption scheme (gpg, jwe)
func GetKeyWrapper(scheme string) KeyWrapper {
	return keyWrappers[scheme]
}

// GetWrappedKeysMap returns a map of wrappedKeys as values in a
// map with the encryption scheme(s) as the key(s)
func GetWrappedKeysMap(desc ocispec.Descriptor) map[string]string {
	wrappedKeysMap := make(map[string]string)

	for annotationsID, scheme := range keyWrapperAnnotations {
		if annotation, ok := desc.Annotations[annotationsID]; ok {
			wrappedKeysMap[scheme] = annotation
		}
	}
	return wrappedKeysMap
}

// EncryptLayer encrypts the layer by running one encryptor after the other
func EncryptLayer(ec *EncryptConfig, encOrPlainLayer []byte, desc ocispec.Descriptor) ([]byte, map[string]string, error) {
	var (
		encLayer []byte
		err      error
		optsData []byte
	)

	symKey := make([]byte, 256/8)
	_, err = io.ReadFull(rand.Reader, symKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not create symmetric key")
	}

	for annotationsID := range keyWrapperAnnotations {
		annotation := desc.Annotations[annotationsID]
		if annotation != "" {
			optsData, err = decryptLayerKeyOptsData(&ec.Dc, desc)
			if err != nil {
				return nil, nil, err
			}
			// already encrypted!
			encLayer = encOrPlainLayer
		}
	}

	newAnnotations := make(map[string]string)

	for annotationsID, scheme := range keyWrapperAnnotations {
		b64Annotations := desc.Annotations[annotationsID]
		if b64Annotations == "" && optsData == nil {
			encLayer, optsData, err = commonEncryptLayer(encOrPlainLayer, symKey, AeadAes256Gcm)
			if err != nil {
				return nil, nil, err
			}
		}
		keywrapper := GetKeyWrapper(scheme)
		b64Annotations, err = preWrapKeys(keywrapper, ec, b64Annotations, optsData)
		if err != nil {
			return nil, nil, err
		}
		if b64Annotations != "" {
			newAnnotations[annotationsID] = b64Annotations
		}
	}
	if len(newAnnotations) == 0 {
		err = errors.Errorf("No encryptor found to handle encryption")
	}
	// if nothing was encrypted, we just return encLayer = nil
	return encLayer, newAnnotations, err
}

// preWrapKeys calls WrapKeys and handles the base64 encoding and concatenation of the
// annotation data
func preWrapKeys(keywrapper KeyWrapper, ec *EncryptConfig, b64Annotations string, optsData []byte) (string, error) {
	newAnnotation, err := keywrapper.WrapKeys(ec, optsData)
	if err != nil || len(newAnnotation) == 0 {
		return b64Annotations, err
	}
	b64newAnnotation := base64.StdEncoding.EncodeToString(newAnnotation)
	if b64Annotations == "" {
		return b64newAnnotation, nil
	}
	return b64Annotations + "," + b64newAnnotation, nil
}

// DecryptLayer decrypts a layer trying one KeyWrapper after the other to see whether it
// can apply the provided private key
func DecryptLayer(dc *DecryptConfig, encLayer []byte, desc ocispec.Descriptor) ([]byte, error) {
	optsData, err := decryptLayerKeyOptsData(dc, desc)
	if err != nil {
		return nil, err
	}

	return commonDecryptLayer(encLayer, optsData)
}

func decryptLayerKeyOptsData(dc *DecryptConfig, desc ocispec.Descriptor) ([]byte, error) {
	for annotationsID, scheme := range keyWrapperAnnotations {
		b64Annotation := desc.Annotations[annotationsID]
		if b64Annotation != "" {
			keywrapper := GetKeyWrapper(scheme)
			optsData, err := preUnwrapKey(keywrapper, dc, b64Annotation)
			if err != nil {
				// try next KeyWrapper
				continue
			}
			if optsData == nil {
				// try next KeyWrapper
				continue
			}
			return optsData, nil
		}
	}
	return nil, errors.Errorf("No suitable key unwrapper found")
}

// preUnwrapKey decodes the comma separated base64 strings and calls the Unwrap function
// of the given keywrapper with it and returns the result in case the Unwrap functions
// does not return an error. If all attempts fail, an error is returned.
func preUnwrapKey(keywrapper KeyWrapper, dc *DecryptConfig, b64Annotations string) ([]byte, error) {
	if b64Annotations == "" {
		return nil, nil
	}
	for _, b64Annotation := range strings.Split(b64Annotations, ",") {
		annotation, err := base64.StdEncoding.DecodeString(b64Annotation)
		if err != nil {
			return nil, errors.New("Could not base64 decode the annotation")
		}
		optsData, err := keywrapper.UnwrapKey(dc, annotation)
		if err != nil {
			continue
		}
		return optsData, nil
	}
	return nil, errors.New("No suitable key found for decrypting layer key")
}

// commonEncryptLayer is a function to encrypt the plain layer using a new random
// symmetric key and return the LayerBlockCipherHandler's JSON in string form for
// later use during decryption
func commonEncryptLayer(plainLayer []byte, symKey []byte, typ LayerCipherType) ([]byte, []byte, error) {
	opts := LayerBlockCipherOptions{
		SymmetricKey: symKey,
	}
	lbch, err := NewLayerBlockCipherHandler()
	if err != nil {
		return nil, nil, err
	}

	encLayer, opts, err := lbch.Encrypt(plainLayer, typ, opts)
	if err != nil {
		return nil, nil, err
	}

	optsData, err := json.Marshal(opts)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not JSON marshal opts")
	}
	return encLayer, optsData, err
}

// commonDecryptLayer decrypts an encrypted layer previously encrypted with commonEncryptLayer
// by passing along the optsData
func commonDecryptLayer(encLayer []byte, optsData []byte) ([]byte, error) {
	opts := LayerBlockCipherOptions{}
	err := json.Unmarshal(optsData, &opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not JSON unmarshal optsData")
	}

	lbch, err := NewLayerBlockCipherHandler()
	if err != nil {
		return nil, err
	}

	plainLayer, opts, err := lbch.Decrypt(encLayer, opts)
	if err != nil {
		return nil, err
	}

	return plainLayer, nil
}
