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

	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/images"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
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
	}, cli.StringSliceFlag{
		Name:  "key",
		Usage: "A secret key's filename; may be provided multiple times",
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

		gpgVault := images.NewGPGVault()
		err = gpgVault.AddSecretKeyRingFiles(context.StringSlice("key"))
		if err != nil {
			return err
		}

		layerSymKeyMap, err := images.GetSymmetricKeys(layerInfos, gpgClient, gpgVault)
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
