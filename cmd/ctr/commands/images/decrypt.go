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
	"fmt"
	"os"
	"strings"

	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"golang.org/x/crypto/ssh/terminal"
)

var decryptCommand = cli.Command{
	Name:      "decrypt",
	Usage:     "decrypt an image locally",
	ArgsUsage: "[flags] <local> <new name>",
	Description: `Decrypt an image locally.

	Decrypt an image using private keys managed by GPG.
	The user has contol over which layers to decrypt and for which platform.
	If no payers or platforms are specified, all layers for all platforms are
	decrypted.
`,
	Flags: append(commands.RegistryFlags, cli.IntSliceFlag{
		Name:  "layer",
		Usage: "The layer to decrypt; this must be either the layer number or a negative number starting with -1 for topmost layer",
	}, cli.StringSliceFlag{
		Name:  "platform",
		Usage: "For which platform to decrypt; by default decryption is done for all platforms",
	}, cli.StringFlag{
		Name:  "gpg-homedir",
		Usage: "The GPG homedir to use; by default gpg uses ~/.gnupg",
	}, cli.StringFlag{
		Name:  "gpg-version",
		Usage: "The GPG version (\"v1\" or \"v2\"), default will make an educated guess",
	}),
	Action: func(context *cli.Context) error {
		local := context.Args().First()
		if local == "" {
			return errors.New("please provide the name of an image to decrypt")
		}

		newName := context.Args().Get(1)
		if newName != "" {
			fmt.Printf("Decrypting %s to %s\n", local, newName)
		} else {
			fmt.Printf("Decrypting %s and replacing it with the decrypted image\n", local)
		}
		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		// Create gpg client
		gpgVersion := context.String("gpg-version")
		v := new(images.GPGVersion)
		switch gpgVersion {
		case "v1":
			*v = images.GPGv1
		case "v2":
			*v = images.GPGv2
		default:
			v = nil
		}
		gpgClient, err := images.NewGPGClient(v, context.String("gpg-homedir"))
		if err != nil {
			return errors.New("Unable to create GPG Client")
		}

		layers32 := commands.IntToInt32Array(context.IntSlice("layer"))

		layerInfos, err := client.ImageService().GetImageLayerInfo(ctx, local, layers32, context.StringSlice("platform"))
		if err != nil {
			return err
		}

		isEncrypted := false
		for i := 0; i < len(layerInfos); i++ {
			if len(layerInfos[i].WrappedKeys) > 0 {
				isEncrypted = true
			}
		}
		if !isEncrypted {
			fmt.Printf("Nothing to decrypted.\n")
			return nil
		}

		layerSymKeyMap, err := getSymmetricKeys(layerInfos, gpgClient)
		if err != nil {
			return err
		}
		fmt.Printf("\n")

		cc := &images.CryptoConfig{
			Dc: &images.DecryptConfig{
				LayerSymKeyMap: layerSymKeyMap,
			},
		}
		_, err = client.ImageService().DecryptImage(ctx, local, newName, cc, layers32, context.StringSlice("platform"))

		return err
	},
}

// getSymmetricKeys walks the list of layerInfos and tries to decrypt the
// wrapped symmetric keys. For this it determines which private keys are on
// this system and prompts for the passwords for those that are available.
// If we do not find a private key on the system for getting to the symmetric
// key of a layer then an error is generated. Otherwise the wrapped symmetric
// key is decrypted using the private key and added to a map that describes
// the layer by platform name and layer number as key and the symmetric key
// data as value
func getSymmetricKeys(layerInfos []images.LayerInfo, gpgClient images.GPGClient) (map[string]images.DecryptKeyData, error) {
	type PrivKeyData struct {
		KeyData         []byte
		KeyDataPassword []byte
	}
	var pkd PrivKeyData
	keyIDPasswordMap := make(map[uint64]PrivKeyData)
	layerSymkeyMap := make(map[string]images.DecryptKeyData)

	// we need to decrypt one symmetric key per encrypted layer per platform
	for _, layerInfo := range layerInfos {

		keyIds, err := images.WrappedKeysToKeyIds(layerInfo.WrappedKeys)
		if err != nil {
			return layerSymkeyMap, err
		}

		found := false
		for _, keyid := range keyIds {
			// do we have this key?
			keyinfo, haveKey, _ := gpgClient.GetSecretKeyDetails(keyid)
			// this may fail if the key is not here; we ignore the error
			if !haveKey {
				// key not on this system
				continue
			}

			var ok bool
			if pkd, ok = keyIDPasswordMap[keyid]; !ok {
				fmt.Printf("Passphrase required for Key id 0x%x: \n%v", keyid, string(keyinfo))
				fmt.Printf("Enter passphrase for key with Id 0x%x: ", keyid)

				password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				fmt.Printf("\n")
				if err != nil {
					return layerSymkeyMap, err
				}
				keydata, err := gpgClient.GetGPGPrivateKey(keyid, string(password))
				if err != nil {
					return layerSymkeyMap, err
				}
				pkd = PrivKeyData{
					KeyData:         keydata,
					KeyDataPassword: password,
				}
				keyIDPasswordMap[keyid] = pkd
			}

			symKeyData, symKeyCipher, err := images.DecryptSymmetricKey(layerInfo.WrappedKeys, keyid, pkd.KeyData, pkd.KeyDataPassword, nil)
			if err != nil {
				return layerSymkeyMap, err
			}

			index := fmt.Sprintf("%s:%d", layerInfo.Platform, layerInfo.ID)
			layerSymkeyMap[index] = images.DecryptKeyData{
				SymKeyData:   symKeyData,
				SymKeyCipher: uint8(symKeyCipher),
			}
			found = true
			break
		}
		if !found && len(layerInfo.WrappedKeys) > 0 {
			keyIds, _ := images.WrappedKeysToKeyIds(layerInfo.WrappedKeys)
			ids := commands.Uint64ToStringArray("0x%x", keyIds)

			return layerSymkeyMap, errors.Wrapf(errdefs.ErrNotFound, "Missing key for decryption of layer %d of %s. Need one of the following keys: %s", layerInfo.ID, layerInfo.Platform, strings.Join(ids, ", "))
		}
	}
	return layerSymkeyMap, nil
}
