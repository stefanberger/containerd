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
	"fmt"
	"strings"

	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/images/encryption"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var encryptCommand = cli.Command{
	Name:      "encrypt",
	Usage:     "encrypt an image locally",
	ArgsUsage: "[flags] <local> <new name>",
	Description: `Encrypt an image locally.

	Encrypt an image using public keys managed by GPG.
	The user must provide recpients who will be able to decrypt the image using
	their GPG-managed private key. For this the user's GPG keyring must hold the public
	keys of the recipients.
	The user has control over the individual layers and the platforms they are
	associated with and can encrypt them separately. If no layers or platforms are
	specified, all layers for all platforms will be encrypted.
	This tool also allows management of the recipients of the image through changes
	to the list of recipients.
	Once the image has been encrypted it may be pushed to a registry.
`,
	Flags: append(commands.RegistryFlags, cli.StringSliceFlag{
		Name:  "recipient",
		Usage: "Recipient of the image is the person who can decrypt it",
	}, cli.IntSliceFlag{
		Name:  "layer",
		Usage: "The layer to encrypt; this must be either the layer number or a negative number starting with -1 for topmost layer",
	}, cli.StringSliceFlag{
		Name:  "platform",
		Usage: "For which platform to encrypt; by default encrytion is done for all platforms",
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
		Name:  "dec-recipient",
		Usage: "Recipient of the image; needed for adding recpient; used only for PKCs7 and must be an x509 certificate",
	}),
	Action: func(context *cli.Context) error {
		local := context.Args().First()
		if local == "" {
			return errors.New("please provide the name of an image to encrypt")
		}

		newName := context.Args().Get(1)
		if newName != "" {
			fmt.Printf("Encrypting %s to %s\n", local, newName)
		} else {
			fmt.Printf("Encrypting %s and replacing it with the encrypted image\n", local)
		}
		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		recipients := context.StringSlice("recipient")
		if len(recipients) == 0 {
			return errors.New("no recipients given -- nothing to do")
		}

		layers32 := commands.IntToInt32Array(context.IntSlice("layer"))

		gpgSecretKeyRingFiles, privKeys, err := processPrivateKeyFiles(context.StringSlice("key"))
		if err != nil {
			return err
		}

		gpgRecipients, pubKeys, x509s, err := processRecipientKeys(recipients)
		if err != nil {
			return err
		}

		_, _, decX509s, err := processRecipientKeys(context.StringSlice("dec-recipient"))
		if err != nil {
			return err
		}

		dcparameters := make(map[string]string)
		parameters := make(map[string]string)

		if len(pubKeys) > 0 {
			parameters["pubkeys"] = strings.Join(pubKeys, ",")
		}
		if len(x509s) > 0 {
			parameters["x509s"] = strings.Join(x509s, ",")
		}

		layerInfos, err := client.ImageService().GetImageLayerInfo(ctx, local, layers32, context.StringSlice("platform"))
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

		if len(gpgRecipients) > 0 {
			parameters["gpg-recipients"] = strings.Join(gpgRecipients, ",")

			gpgClient, err := createGPGClient(context)
			if err != nil {
				return err
			}

			gpgPubRingFile, err := gpgClient.ReadGPGPubRingFile()
			if err != nil {
				return err
			}

			parameters["gpg-pubkeyringfile"] = base64.StdEncoding.EncodeToString(gpgPubRingFile)
		}

		if len(privKeys) > 0 {
			dcparameters["privkeys"] = strings.Join(privKeys, ",")
		}
		if len(decX509s) > 0 {
			dcparameters["x509s"] = strings.Join(decX509s, ",")
		}

		cc := &encryption.CryptoConfig{
			Ec: &encryption.EncryptConfig{
				Parameters: parameters,
				Operation:  encryption.OperationAddRecipients,
				Dc: encryption.DecryptConfig{
					Parameters: dcparameters,
				},
			},
		}
		_, err = encryptImage(client, ctx, local, newName, cc, layers32, context.StringSlice("platform"))

		return err
	},
}
