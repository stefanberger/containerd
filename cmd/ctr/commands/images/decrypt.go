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
	"io/ioutil"
	"os/exec"
	"fmt"
	"syscall"

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"golang.org/x/crypto/ssh/terminal"
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

		LayerInfos, err := client.ImageService().GetImageLayerInfo(ctx, local)
		if err != nil {
			return err
		}
		var keyIds []uint64
		for i := 0; i < len(LayerInfos); i++ {
			keyIds = addToSet(keyIds, LayerInfos[i].KeyIds)
		}

		keyIdMap := make(map[uint64]images.DecryptKeyData)
		if len(keyIds) == 0 {
			fmt.Printf("The image is not encrypted.\n")
			return nil
		} else {
			for _, keyid := range keyIds {
				fmt.Printf("Enter password for key with Id 0x%x: ", keyid)
				password, err := terminal.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				keydata, err := GetGPGPrivateKey(keyid, string(password))
				if err != nil {
					return err
				}
				keyIdMap[keyid] = images.DecryptKeyData{
					KeyData:         keydata,
					KeyDataPassword: password,
				}
			}
			fmt.Printf("\n")
		}
		client.ImageService().DecryptImage(ctx, local, newName, &images.CryptoConfig{
			Dc: &images.DecryptConfig {
				KeyIdMap: keyIdMap,
			},
		})

		return nil
	},
}

func GetGPGPrivateKey (keyid uint64, password string) ([]byte, error) {
	args := append([]string{"--pinentry-mode", "loopback", "--passphrase", password,"--export-secret-key"}, fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	keydata, err2 := ioutil.ReadAll(stdout)

	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	return keydata, err2
}

func addToSet(set, add []uint64) []uint64 {
	for i := 0; i < len(add); i++ {
		found := false
		for j := 0; j < len(set); j++ {
			if set[j] == add[i] {
				found = true
				break;
			}
		}
		if !found {
			set = append(set, add[i])
		}
	}
	return set
}

