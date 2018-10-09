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

package pgp

import (
	"github.com/containerd/containerd/images/encryption/config"
	"testing"
)

var validGpgCcs = []*config.CryptoConfig{
	// Key 1
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"gpg-pubkeyringfile": [][]byte{gpgPubKeyRing},
				"gpg-recipients":     [][]byte{gpgRecipient1},
			},
			Operation: config.OperationAddRecipients,
			Dc: config.DecryptConfig{
				Parameters: map[string][][]byte{
					"gpg-privatekeys": [][]byte{gpgPrivKey1},
				},
			},
		},

		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"gpg-privatekeys": [][]byte{gpgPrivKey1},
			},
		},
	},

	// Key 2
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"gpg-pubkeyringfile": [][]byte{gpgPubKeyRing},
				"gpg-recipients":     [][]byte{gpgRecipient2},
			},
			Operation: config.OperationAddRecipients,
			Dc: config.DecryptConfig{
				Parameters: map[string][][]byte{
					"gpg-privatekeys": [][]byte{gpgPrivKey2},
				},
			},
		},

		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"gpg-privatekeys": [][]byte{gpgPrivKey2},
			},
		},
	},

	// Key 1 without enc private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"gpg-pubkeyringfile": [][]byte{gpgPubKeyRing},
				"gpg-recipients":     [][]byte{gpgRecipient1},
			},
			Operation: config.OperationAddRecipients,
		},

		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"gpg-privatekeys": [][]byte{gpgPrivKey1},
			},
		},
	},

	// Key 2 without enc private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"gpg-pubkeyringfile": [][]byte{gpgPubKeyRing},
				"gpg-recipients":     [][]byte{gpgRecipient2},
			},
			Operation: config.OperationAddRecipients,
		},

		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"gpg-privatekeys": [][]byte{gpgPrivKey2},
			},
		},
	},
}

var invalidGpgCcs = []*config.CryptoConfig{
	// Client key 1 public with client 2 private decrypt
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"gpg-pubkeyringfile": [][]byte{gpgPubKeyRing},
				"gpg-recipients":     [][]byte{gpgRecipient1},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"gpg-privatekeys": [][]byte{gpgPrivKey2},
			},
		},
	},

	// Client key 1 public with no private key
	&config.CryptoConfig{
		Ec: &config.EncryptConfig{
			Parameters: map[string][][]byte{
				"gpg-pubkeyringfile": [][]byte{gpgPubKeyRing},
				"gpg-recipients":     [][]byte{gpgRecipient1},
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
				"gpg-pubkeyringfile": [][]byte{gpgPrivKey1},
				"gpg-recipients":     [][]byte{gpgRecipient1},
			},
			Operation: config.OperationAddRecipients,
		},
		Dc: &config.DecryptConfig{
			Parameters: map[string][][]byte{
				"gpg-privatekeys": [][]byte{gpgPrivKey1},
			},
		},
	},
}

func TestKeyWrapGpgSuccess(t *testing.T) {
	for _, cc := range validGpgCcs {
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

func TestKeyWrapGpgInvalid(t *testing.T) {
	for _, cc := range invalidGpgCcs {
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
