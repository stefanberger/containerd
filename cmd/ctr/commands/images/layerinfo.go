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
	"strconv"
	"text/tabwriter"

	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var layerinfoCommand = cli.Command{
	Name:      "layerinfo",
	Usage:     "get infomration about an image's layers",
	ArgsUsage: "[flags] <local>",
	Description: `Get encryption information about the layers of an image.

	XYZ
`,
	Flags: commands.RegistryFlags,
	Action: func(context *cli.Context) error {
		var (
			local = context.Args().First()
		)
		if local == "" {
			return errors.New("please provide the name of an image to decrypt")
		}
		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		LayerInfos, err := client.ImageService().GetImageLayerInfo(ctx, local)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.AlignRight)
		fmt.Fprintf(w, "Num\tDigest\tArchitecture\tSize\tEncryption\tKey IDs\t\n")
		for _, layer := range LayerInfos {
			keyids := ""
			for _, keyid := range layer.KeyIds {
				if keyids != "" {
					keyids = keyids + ", "
				}
				keyids = keyids + "0x" + strconv.FormatUint(keyid, 16)
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t\n", layer.Id, layer.Digest, layer.Architecture, layer.FileSize, layer.Encryption, keyids)
		}
		w.Flush()
		return nil
	},
}


