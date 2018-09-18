package encryption

// WrappedKeyService provides an interface to wrap and unwrap keys, and is built
// to be extensible to a plugin call or remote grpc call.
type WrappedKeyService interface {
	Wrap(req *WrapKeyRequest) (*WrapKeyResponse, error)
	Unwrap(req *UnwrapKeyRequest) (*UnwrapKeyResponse, error)
}

// WrapKeyRequest is a request for function WrappedKeyService.Wrap
type WrapKeyRequest struct {
	// Key is the key bytes to be wrapped
	Key []byte `json:'key'`
	// Opt contains the encryption options needed to wrap the key, can include keyrings and private keys
	Opt map[string]string `json:'opt'`
}

// WrapKeyRequest is a response for function WrappedKeyService.Wrap
type WrapKeyResponse struct {
	// WrappedKeys contains an array of wrapped keys that should be base64 encoded in org...image.enc.keys.*
	WrappedKeys [][]byte `json:'wrappedkeys'`
}

// UnwrapKeyRequest is a request for function WrappedKeyService.Unwrap
type UnwrapKeyRequest struct {
	// Keys are the ',' delimetered base64 decoded content of org...image.enc.keys.*
	WrappedKeys [][]byte `json:'wrappedkeys'`
	// Opt contains the encryption options needed to unwrap keys, can include keyrings and private keys
	Opt map[string]string `json:'opt'`
}

// UnwrapKeyRequest is a response for function WrappedKeyService.Unwrap
type UnwrapKeyResponse struct {
	Key []byte `json:'key'`
}
