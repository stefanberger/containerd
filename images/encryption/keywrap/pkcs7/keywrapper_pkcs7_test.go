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

package pkcs7

import (
	"github.com/containerd/containerd/images/encryption/config"
	"testing"
)

var validPkcs7Ccs = []*config.CryptoConfig{
	// Client key 1
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7ClientCert},
			},
			Operation: config.OperationAddRecipients,
			Dc: config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys": [][]byte{pkcs7ClientCertKey},
					"x509s":    [][]byte{pkcs7ClientCert},
				},
			},
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"privkeys": [][]byte{pkcs7ClientCertKey},
				"x509s":    [][]byte{pkcs7ClientCert},
			},
		},
	},

	// Client key 2
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7Client2Cert},
			},
			Operation: config.OperationAddRecipients,
			Dc: config.DecryptConfig{
				Parameters: map[string][][]byte{
					"privkeys": [][]byte{pkcs7Client2CertKey},
					"x509s":    [][]byte{pkcs7Client2Cert},
				},
			},
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"privkeys": [][]byte{pkcs7Client2CertKey},
				"x509s":    [][]byte{pkcs7Client2Cert},
			},
		},
	},

	// Client key 1 without enc private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7ClientCert},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"privkeys": [][]byte{pkcs7ClientCertKey},
				"x509s":    [][]byte{pkcs7ClientCert},
			},
		},
	},

	// Client key 2 without enc private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7Client2Cert},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"privkeys": [][]byte{pkcs7Client2CertKey},
				"x509s":    [][]byte{pkcs7Client2Cert},
			},
		},
	},
}

var invalidPkcs7Ccs = []*config.CryptoConfig{
	// Client key 1 public with client 2 private decrypt
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7ClientCert},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"privkeys": [][]byte{pkcs7Client2CertKey},
				"x509s":    [][]byte{pkcs7Client2Cert},
			},
		},
	},

	// Client key 1 public with no private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7ClientCert},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{},
		},
	},

	// Invalid Client key 1 private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"x509s": [][]byte{pkcs7ClientCertKey},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"privkeys": [][]byte{pkcs7ClientCert},
				"x509s":    [][]byte{pkcs7ClientCert},
			},
		},
	},
}

func TestKeyWrapPkcs7Success(t *testing.T) {
	for _, cc := range validPkcs7Ccs {
		kw := NewKeyWrapper()

		data := []byte("This is some secret text")

		wk, err := kw.WrapKeys(cc.Ec, data)
		if err != nil {
			t.Fatal(err)
		}

		ud, err := kw.UnwrapKey(cc.Dc, wk)
		if err != nil {
			t.Fatal(err)
		}

		if string(data) != string(ud) {
			t.Fatal("Strings don't match")
		}
	}
}

func TestKeyWrapPkcs7Invalid(t *testing.T) {
	for _, cc := range invalidPkcs7Ccs {
		kw := NewKeyWrapper()

		data := []byte("This is some secret text")

		wk, err := kw.WrapKeys(cc.Ec, data)
		if err != nil {
			return
		}

		ud, err := kw.UnwrapKey(cc.Dc, wk)
		if err != nil {
			return
		}

		if string(data) != string(ud) {
			return
		}

		t.Fatal("Successfully wrap for invalid crypto config")
	}
}
