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

package keywrap

import (
	"github.com/containerd/containerd/images/encryption/config"
)

// KeyWrapper is the interface used for wrapping keys using
// a specific encryption technology (pgp, jwe)
type KeyWrapper interface {
	WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error)
	UnwrapKey(dc *config.DecryptConfig, annotation []byte) ([]byte, error)
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
