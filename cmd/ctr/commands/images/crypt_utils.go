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

package images

import (
	"encoding/base64"
	"io/ioutil"
	"strings"

	"github.com/containerd/containerd/images/encryption"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

func processRecipientKeys(recipients []string) ([]string, []string, error) {
	var (
		gpgRecipients []string
		pubkeys       []string
	)
	for _, recipient := range recipients {
		if strings.HasSuffix(recipient, ".pem") || strings.HasSuffix(recipient, ".der") {
			tmp, err := ioutil.ReadFile(recipient)
			if err != nil {
				return nil, nil, err
			}
			pubkeys = append(pubkeys, base64.StdEncoding.EncodeToString(tmp))
		} else {
			gpgRecipients = append(gpgRecipients, recipient)
		}
	}
	return gpgRecipients, pubkeys, nil
}

func processPrivateKeyFiles(keyFiles []string) ([]string, []string, error) {
	var (
		gpgSecretKeyRingFiles []string
		privkeys              []string
	)
	// keys needed for decryption in case of adding a recipient
	for _, keyfile := range keyFiles {
		if strings.HasSuffix(keyfile, ".pem") || strings.HasSuffix(keyfile, ".der") {
			tmp, err := ioutil.ReadFile(keyfile)
			if err != nil {
				return nil, nil, err
			}
			privkeys = append(privkeys, base64.StdEncoding.EncodeToString(tmp))
		} else {
			gpgSecretKeyRingFiles = append(gpgSecretKeyRingFiles, keyfile)
		}
	}
	return gpgSecretKeyRingFiles, privkeys, nil
}

func setupGPGClient(context *cli.Context, gpgSecretKeyRingFiles []string, layerInfos []encryption.LayerInfo, mustFindKey bool) (encryption.GPGClient, encryption.GPGVault, map[string]string, error) {
	gpgVersion := context.String("gpg-version")
	v := new(encryption.GPGVersion)
	switch gpgVersion {
	case "v1":
		*v = encryption.GPGv1
	case "v2":
		*v = encryption.GPGv2
	default:
		v = nil
	}
	gpgClient, err := encryption.NewGPGClient(v, context.String("gpg-homedir"))
	if err != nil {
		return nil, nil, nil, errors.New("Unable to create GPG Client")
	}

	gpgVault := encryption.NewGPGVault()
	err = gpgVault.AddSecretKeyRingFiles(gpgSecretKeyRingFiles)
	if err != nil {
		return nil, nil, nil, err
	}
	dcparameters, err := encryption.GPGGetPrivateKey(layerInfos, gpgClient, gpgVault, mustFindKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return gpgClient, gpgVault, dcparameters, nil
}
