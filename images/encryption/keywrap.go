package encryption

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// KeyWrapper is the interface used for wrapping keys using
// a specific encryption technology (pgp, jwe)
type KeyWrapper interface {
	WrapKeys(ec *EncryptConfig, optsData []byte) ([]byte, error)
	UnwrapKey(dc *DecryptConfig, annotation []byte) ([]byte, error)
	GetAnnotationID() string
	// GetPrivateKeys (optional) gets the string of private keys. It is an optional implementation
	// as in some key services, a private key may not be exportable (i.e. HSM)
	GetPrivateKeys(dcparameters map[string]string) string

	// GetKeyIdsFromPacket (optional) gets a list of key IDs. This is optional as some encryption
	// schemes may not have a notion of key IDs
	GetKeyIdsFromPacket(packet string) ([]uint64, error)

	// GetRecipients (optional) gets a list of recipients. It is optional due to the validity of
	// recipients in a particular encryptiong scheme
	GetRecipients(packet string) ([]string, error)
}

func init() {
	keyWrappers = make(map[string]KeyWrapper)
	keyWrapperAnnotations = make(map[string]string)
	registerKeyWrapper("pgp", &gpgKeyWrapper{})
	registerKeyWrapper("jwe", &jweKeyWrapper{})
	registerKeyWrapper("pkcs7", &pkcs7KeyWrapper{})
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
