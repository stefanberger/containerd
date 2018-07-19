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

var encryptCommand = cli.Command{
	Name:      "encrypt",
	Usage:     "encrypt an image locally",
	ArgsUsage: "[flags] <local> <new name>",
	Description: `Encrypt and image.

	XYZ
`,
	Flags: append(commands.RegistryFlags, cli.StringSliceFlag{
		Name:  "recipient",
		Usage: "Recipient of the image is the person who can decrypt it",
	}),
	Action: func(context *cli.Context) error {
		var (
			local = context.Args().First()
			newName = context.Args().Get(1)
		)
		if local == "" {
			return errors.New("please provide the name of an image to encrypt")
		}
		if newName == "" {
			return errors.New("please provide a name for the encrypted image")
		}
		fmt.Printf("Encrypting %s to %s\n", local, newName)
		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()
		img, err := client.ImageService().Get(ctx, local)
		if err != nil {
			return errors.Wrap(err, "unable to resolve image to manifest")
		}

		var ec *images.EncryptConfig
		recipients := context.StringSlice("recipient")
		if len(recipients) == 0 {
			return errors.New("no recipients given -- nothing to do")			
		}

		gpgPubRingFile, err := images.ReadGPGPubRingFile()
		if err != nil {
			return err
		}
		ec = &images.EncryptConfig{
			GPGPubRingFile: gpgPubRingFile,
			Recipients:     recipients,
		}
		img, err = client.ImageService().EncryptImage(ctx, local, newName, ec)
		if err != nil {
			return err
		}
		fmt.Printf("local: %s,  img.Name: %s", local, img.Name)
		return nil
	},
}

