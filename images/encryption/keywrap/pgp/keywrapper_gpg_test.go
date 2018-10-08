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
	"testing"
)

var validGpgCcs = []*CryptoConfig{
	// Key 1
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPubKeyRing,
				"gpg-recipients":     gpgRecipient1,
			},
			Operation: OperationAddRecipients,
			Dc: DecryptConfig{
				Parameters: map[string]string{
					"gpg-privatekeys": gpgPrivKey1,
				},
			},
		},

		Dc: &DecryptConfig{
			Parameters: map[string]string{
				"gpg-privatekeys": gpgPrivKey1,
			},
		},
	},

	// Key 2
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPubKeyRing,
				"gpg-recipients":     gpgRecipient2,
			},
			Operation: OperationAddRecipients,
			Dc: DecryptConfig{
				Parameters: map[string]string{
					"gpg-privatekeys": gpgPrivKey2,
				},
			},
		},

		Dc: &DecryptConfig{
			Parameters: map[string]string{
				"gpg-privatekeys": gpgPrivKey2,
			},
		},
	},

	// Key 1 without enc private key
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPubKeyRing,
				"gpg-recipients":     gpgRecipient1,
			},
			Operation: OperationAddRecipients,
		},

		Dc: &DecryptConfig{
			Parameters: map[string]string{
				"gpg-privatekeys": gpgPrivKey1,
			},
		},
	},

	// Key 2 without enc private key
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPubKeyRing,
				"gpg-recipients":     gpgRecipient2,
			},
			Operation: OperationAddRecipients,
		},

		Dc: &DecryptConfig{
			Parameters: map[string]string{
				"gpg-privatekeys": gpgPrivKey2,
			},
		},
	},
}

var invalidGpgCcs = []*CryptoConfig{
	// Client key 1 public with client 2 private decrypt
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPubKeyRing,
				"gpg-recipients":     gpgRecipient1,
			},
			Operation: OperationAddRecipients,
		},
		Dc: &DecryptConfig{
			Parameters: map[string]string{
				"gpg-privatekeys": gpgPrivKey2,
			},
		},
	},

	// Client key 1 public with no private key
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPubKeyRing,
				"gpg-recipients":     gpgRecipient1,
			},
			Operation: OperationAddRecipients,
		},
		Dc: &DecryptConfig{
			Parameters: map[string]string{},
		},
	},

	// Invalid Client key 1 private key
	&CryptoConfig{
		Ec: &EncryptConfig{
			Parameters: map[string]string{
				"gpg-pubkeyringfile": gpgPrivKey1,
				"gpg-recipients":     gpgRecipient1,
			},
			Operation: OperationAddRecipients,
		},
		Dc: &DecryptConfig{
			Parameters: map[string]string{
				"gpg-privatekeys": gpgPrivKey1,
			},
		},
	},
}

func TestKeyWrapGpgSuccess(t *testing.T) {
	for _, cc := range validGpgCcs {
		kw, ok := keyWrappers["pgp"]
		if !ok {
			t.Fatal("Unable to find key wrap service")
		}

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
		kw, ok := keyWrappers["pgp"]
		if !ok {
			t.Fatal("Unable to find key wrap service")
		}

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
