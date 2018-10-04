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
	"testing"
)

var jweCc = &CryptoConfig{
	Ec: &EncryptConfig{
		Parameters: map[string]string{
			"pubkeys": jwePubKeyPem,
		},
		Operation: OperationAddRecipients,
		Dc: DecryptConfig{
			Parameters: map[string]string{
				"privkeys": jwePrivKeyPem,
			},
		},
	},

	Dc: &DecryptConfig{
		Parameters: map[string]string{
			"privkeys": jwePrivKeyPem,
		},
	},
}

func TestKeyWrapJwe(t *testing.T) {
	kw, ok := keyWrappers["jwe"]
	if !ok {
		t.Fatal("Unable to find key wrap service")
	}

	data := []byte("This is some secret text")

	wk, err := kw.WrapKeys(jweCc.Ec, data)
	if err != nil {
		t.Fatal(err)
	}

	ud, err := kw.UnwrapKey(jweCc.Dc, wk)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != string(ud) {
		t.Fatal("Strings don't match")
	}
}
