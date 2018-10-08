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
	"strings"

	"github.com/containerd/containerd/cmd/ctr/commands"
	encconfig "github.com/containerd/containerd/images/encryption/config"
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
		Usage: "A secret key's filename. The file suffix must be .pem or .der for JWE and anything else for OpenPGP; this option may be provided multiple times",
	}, cli.StringSliceFlag{
		Name:  "recipient",
		Usage: "Recipient of the image; used only for PKCs7 and must be an x509 certificate",
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

		layers32 := commands.IntToInt32Array(context.IntSlice("layer"))

		layerInfos, err := getImageLayerInfo(client, ctx, local, layers32, context.StringSlice("platform"))
		if err != nil {
			return err
		}

		isEncrypted := false
		for i := 0; i < len(layerInfos); i++ {
			if len(layerInfos[i].Descriptor.Annotations) > 0 {
				isEncrypted = true
				break
			}
		}
		if !isEncrypted {
			fmt.Printf("Nothing to decrypted.\n")
			return nil
		}

		dcparameters := make(map[string]string)

		// x509 cert is needed for PCS7 decryption
		_, _, x509s, err := processRecipientKeys(context.StringSlice("recipient"))
		if err != nil {
			return err
		}

		gpgSecretKeyRingFiles, privKeys, err := processPrivateKeyFiles(context.StringSlice("key"))
		if err != nil {
			return err
		}

		if len(privKeys) == 0 {
			// Get pgp private keys from keyring only if no private key was passed
			err = getGPGPrivateKeys(context, gpgSecretKeyRingFiles, layerInfos, true, dcparameters)
			if err != nil {
				return err
			}
		}

		if len(privKeys) > 0 {
			dcparameters["privkeys"] = strings.Join(privKeys, ",")
		}
		if len(x509s) > 0 {
			dcparameters["x509s"] = strings.Join(x509s, ",")
		}

		cc := &encconfig.CryptoConfig{
			Dc: &encconfig.DecryptConfig{
				Parameters: dcparameters,
			},
		}
		_, err = decryptImage(client, ctx, local, newName, cc, layers32, context.StringSlice("platform"))

		return err
	},
}
