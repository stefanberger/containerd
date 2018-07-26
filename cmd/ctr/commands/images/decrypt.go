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
	"syscall"

	"github.com/containerd/containerd/cmd/ctr/commands"
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
		var (
			local   = context.Args().First()
			newName = context.Args().Get(1)
		)
		fmt.Printf("pl: %s\n", context.StringSlice("platform"))
		if local == "" {
			return errors.New("please provide the name of an image to decrypt")
		}
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
			if len(layerInfos[i].KeyIds) > 0 {
				isEncrypted = true
			}
		}
		if !isEncrypted {
			fmt.Printf("Nothing to decrypted.\n")
			return nil
		}

		keyIdMap, err := getPrivateKeys(layerInfos, gpgClient)

		fmt.Printf("\n")
		_, err = client.ImageService().DecryptImage(ctx, local, newName, &images.CryptoConfig{
			Dc: &images.DecryptConfig{
				KeyIdMap: keyIdMap,
			},
		}, layers32, context.StringSlice("platform"))
		return err
	},
}

func addToSet(set, add []uint64) []uint64 {
	for i := 0; i < len(add); i++ {
		found := false
		for j := 0; j < len(set); j++ {
			if set[j] == add[i] {
				found = true
				break
			}
		}
		if !found {
			set = append(set, add[i])
		}
	}
	return set
}

// getPrivateKeys walks the list of layerInfos and determines which keys are on this system
// and prompts for the passwords for those that are available. If one layer does not have
// a private key an error is thrown.
func getPrivateKeys(layerInfos []images.LayerInfo, gpgClient images.GPGClient) (map[uint64]images.DecryptKeyData, error) {
	keyIdMap := make(map[uint64]images.DecryptKeyData)

	// we need one key per encrypted layer
	for _, layerInfo := range layerInfos {
		found := false
		for _, keyid := range layerInfo.KeyIds {
			if _, ok := keyIdMap[keyid]; ok {
				// password already there
				found = true
				break
			}
			// do we have this key?
			keyinfo, haveKey, err := gpgClient.GetSecretKeyDetails(keyid)
			// this may fail if the key is not here; we ignore the error
			if !haveKey {
				// key not on this system
				continue
			}

			fmt.Printf("Passphrase required for Key id 0x%x: \n%v", keyid, string(keyinfo))
			fmt.Printf("Enter passphrase for key with Id 0x%x: ", keyid)

			password, err := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Printf("\n")
			if err != nil {
				return keyIdMap, err
			}

			keydata, err := gpgClient.GetGPGPrivateKey(keyid, string(password))
			if err != nil {
				return keyIdMap, err
			}
			keyIdMap[keyid] = images.DecryptKeyData{
				KeyData:         keydata,
				KeyDataPassword: password,
			}
			found = true
			break
		}
		if !found && len(layerInfo.KeyIds) > 0 {
			return keyIdMap, fmt.Errorf("Missing key for decryption of layer %d of %s. Need one of the following keys: %v\n", layerInfo.Id, layerInfo.Platform, layerInfo.KeyIds)
		}
	}
	return keyIdMap, nil
}
