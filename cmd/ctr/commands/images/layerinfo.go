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
	"strings"
	"text/tabwriter"

	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/images"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var layerinfoCommand = cli.Command{
	Name:      "layerinfo",
	Usage:     "get information about an image's layers",
	ArgsUsage: "[flags] <local>",
	Description: `Get encryption information about the layers of an image.

	Get information about the layers of an image and display with which
	encryption technology the individual layers are encrypted with.
	The user has control over the individual layers and the platforms they are
	associated with and can retrieve information for them separately. If no
	layers or platforms are specified, infomration for all layers and all
	platforms will be retrieved.
`,
	Flags: append(commands.RegistryFlags, cli.IntSliceFlag{
		Name:  "layer",
		Usage: "The layer to get info for; this must be either the layer number or a negative number starting with -1 for topmost layer",
	}, cli.StringSliceFlag{
		Name:  "platform",
		Usage: "For which platform to get the layer info; by default info for all platforms is retrieved",
	}),
	Action: func(context *cli.Context) error {
		local := context.Args().First()
		if local == "" {
			return errors.New("please provide the name of an image to decrypt")
		}
		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		layers32 := commands.IntToInt32Array(context.IntSlice("layer"))

		LayerInfos, err := client.ImageService().GetImageLayerInfo(ctx, local, layers32, context.StringSlice("platform"))
		if err != nil {
			return err
		}
		if len(LayerInfos) == 0 {
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.AlignRight)
		fmt.Fprintf(w, "#\tDIGEST\tPLATFORM\tSIZE\tENCRYPTION\tKEY IDS\t\n")
		for _, layer := range LayerInfos {
			keyIds, err := images.WrappedKeysToKeyIds(layer.WrappedKeys)
			if err != nil {
				return err
			}

			var array []string
			for _, keyid := range keyIds {
				array = append(array, "0x"+strconv.FormatUint(keyid, 16))
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t\n", layer.ID, layer.Digest, layer.Platform, layer.FileSize, layer.Encryption, strings.Join(array, ", "))
		}
		w.Flush()
		return nil
	},
}
