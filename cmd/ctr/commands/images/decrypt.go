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
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var decryptCommand = cli.Command{
	Name:      "decrypt",
	Usage:     "decrypt an image locally",
	ArgsUsage: "[flags] <local> <new name>",
	Description: `Encrypt and image.

	XYZ
`,
	Flags: append(commands.RegistryFlags, cli.StringSliceFlag{
		Name:  "foo",
		Usage: "foo",
	}),
	Action: func(context *cli.Context) error {
		var (
			local = context.Args().First()
			newName = context.Args().Get(1)
		)
		if local == "" {
			return errors.New("please provide the name of an image to decrypt")
		}
		if newName != "" {
			fmt.Printf("Decrypting %s to %s\n", local, newName)
		} else {
			fmt.Printf("Decrypting %s and replacing it with the decrypted image\n", local);
		}
		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		keyIds, err := client.ImageService().GetImageKeyIds(ctx, local)
		if err != nil {
			return err
		}
		if len(keyIds) == 0 {
			fmt.Printf("Image is not encrypted.\n")
		} else {
			fmt.Printf("Image is encrypted to the following keys: ")
			for _, keyid := range keyIds {
				fmt.Printf("0x%x ", keyid)
			}
			fmt.Printf("\n")
		}
		return nil
	},
}

