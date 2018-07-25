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
	Description: `Encrypt and image.

	XYZ
`,
	Flags: append(commands.RegistryFlags, cli.IntSliceFlag{
		Name:  "layer",
		Usage: "The layer to decrypt; this must be either the layer number or a negative number starting with -1 for topmost layer",
	}, cli.StringSliceFlag{
		Name:  "platform",
		Usage: "For which platform to decrypt; by default decryption is done for all platforms",
	}),
	Action: func(context *cli.Context) error {
		var (
			local = context.Args().First()
			newName = context.Args().Get(1)
		)
		fmt.Printf("pl: %s\n", context.StringSlice("platform"))
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

		LayerInfos, err := client.ImageService().GetImageLayerInfo(ctx, local, context.IntSlice("layer"), context.StringSlice("platform"))
		if err != nil {
			return err
		}

		isEncrypted := false
		for i := 0; i < len(LayerInfos); i++ {
			if len(LayerInfos[i].KeyIds) > 0 {
				isEncrypted = true
			}
		}
		if !isEncrypted {
			fmt.Printf("Nothing to decrypted.\n")
			return nil
		}

		keyIdMap := make(map[uint64]images.DecryptKeyData)

		// we need one key per encrypted layer
		for _, LayerInfo := range LayerInfos {
			found := false
			for _, keyid := range LayerInfo.KeyIds {
				if _, ok := keyIdMap[keyid]; ok {
					// password already there
					found = true
					break
				}
				// do we have this key?
				haveKey, _ := HaveGPGPrivateKey(keyid)
				// this may fail if the key is not here; we ignore the error
				if !haveKey {
					// key not on this system
					continue
				}
				fmt.Printf("Enter password for key with Id 0x%x: ", keyid)
				password, err := terminal.ReadPassword(int(syscall.Stdin))
				fmt.Printf("\n")
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
				found = true
				break
			}
			if !found && len(LayerInfo.KeyIds) > 0 {
				return fmt.Errorf("Missing key for decryption of layer %d of %s. Need one of the following keys: %s\n", LayerInfo.Id, LayerInfo.Platform, LayerInfo.KeyIds)
			}
		}
		fmt.Printf("\n")
		_, err = client.ImageService().DecryptImage(ctx, local, newName, &images.CryptoConfig{
			Dc: &images.DecryptConfig {
				KeyIdMap: keyIdMap,
			},
		}, context.IntSlice("layer"), context.StringSlice("platform"))
		return err
	},
}

func HaveGPGPrivateKey(keyid uint64) (bool, error) {
	args := append([]string{"-K"}, fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	if err := cmd.Start(); err != nil {
		return false, err
	}

	if err := cmd.Wait(); err != nil {
		return false, err
	}
	return true, nil
}

func GetGPGPrivateKey (keyid uint64, password string) ([]byte, error) {
	args := append([]string{"--pinentry-mode", "loopback", "--passphrase", password,"--export-secret-key"}, fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	keydata, err2 := ioutil.ReadAll(stdout)
	message, _ := ioutil.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("Error from gpg2: %s\n", message)
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

