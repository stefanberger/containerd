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
	gocontext "context"

	"fmt"
	"io/ioutil"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/encryption"
	encconfig "github.com/containerd/containerd/images/encryption/config"
	encutils "github.com/containerd/containerd/images/encryption/utils"
	"github.com/containerd/containerd/platforms"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli"
)

func processRecipientKeys(recipients []string) ([][]byte, [][]byte, [][]byte, error) {
	var (
		gpgRecipients [][]byte
		pubkeys       [][]byte
		x509s         [][]byte
	)
	for _, recipient := range recipients {
		tmp, err := ioutil.ReadFile(recipient)
		if err != nil {
			gpgRecipients = append(gpgRecipients, []byte(recipient))
			continue
		}
		if encutils.IsCertificate(tmp) {
			x509s = append(x509s, tmp)
		} else if encutils.IsPublicKey(tmp) {
			pubkeys = append(pubkeys, tmp)
		} else {
			gpgRecipients = append(gpgRecipients, []byte(recipient))
		}
	}
	return gpgRecipients, pubkeys, x509s, nil
}

func processPrivateKeyFiles(keyFiles []string) ([][]byte, [][]byte, error) {
	var (
		gpgSecretKeyRingFiles [][]byte
		privkeys              [][]byte
	)
	// keys needed for decryption in case of adding a recipient
	for _, keyfile := range keyFiles {
		tmp, err := ioutil.ReadFile(keyfile)
		if err != nil {
			return nil, nil, err
		}
		if encutils.IsPrivateKey(tmp) {
			privkeys = append(privkeys, tmp)
		} else if encutils.IsGPGPrivateKeyRing(tmp) {
			gpgSecretKeyRingFiles = append(gpgSecretKeyRingFiles, tmp)
		} else {
			return nil, nil, fmt.Errorf("Unidentified private key in file %s", keyfile)
		}
	}
	return gpgSecretKeyRingFiles, privkeys, nil
}

func createGPGClient(context *cli.Context) (encryption.GPGClient, error) {
	return encryption.NewGPGClient(context.String("gpg-version"), context.String("gpg-homedir"))
}

func getGPGPrivateKeys(context *cli.Context, gpgSecretKeyRingFiles [][]byte, layerInfos []encryption.LayerInfo, mustFindKey bool, dcparameters map[string][][]byte) error {
	gpgClient, err := createGPGClient(context)
	if err != nil {
		return err
	}

	var gpgVault encryption.GPGVault
	if len(gpgSecretKeyRingFiles) > 0 {
		gpgVault = encryption.NewGPGVault()
		err = gpgVault.AddSecretKeyRingDataArray(gpgSecretKeyRingFiles)
		if err != nil {
			return err
		}
	}
	return encryption.GPGGetPrivateKey(layerInfos, gpgClient, gpgVault, mustFindKey, dcparameters)
}

// cryptImage encrypts or decrypts an image with the given name and stores it either under the newName
// or updates the existing one
func cryptImage(client *containerd.Client, ctx gocontext.Context, name, newName string, cc *encconfig.CryptoConfig, layers []int32, platformList []string, encrypt bool) (images.Image, error) {
	s := client.ImageService()

	image, err := s.Get(ctx, name)
	if err != nil {
		return images.Image{}, err
	}

	pl, err := platforms.ParseArray(platformList)
	if err != nil {
		return images.Image{}, err
	}

	lf := &encryption.LayerFilter{
		Layers:    layers,
		Platforms: pl,
	}

	var (
		modified bool
		newSpec  ocispec.Descriptor
	)
	if encrypt {
		newSpec, modified, err = images.EncryptImage(ctx, client.ContentStore(), image.Target, cc, lf)
	} else {
		newSpec, modified, err = images.DecryptImage(ctx, client.ContentStore(), image.Target, cc, lf)
	}
	if err != nil {
		return image, err
	}
	if !modified {
		return image, nil
	}

	image.Target = newSpec

	// if newName is either empty or equal to the existing name, it's an update
	if newName == "" || strings.Compare(image.Name, newName) == 0 {
		// first Delete the existing and then Create a new one
		// We have to do it this way since we have a newSpec!
		err = s.Delete(ctx, image.Name)
		if err != nil {
			return images.Image{}, err
		}
		newName = image.Name
	}

	image.Name = newName
	return s.Create(ctx, image)
}

func encryptImage(client *containerd.Client, ctx gocontext.Context, name, newName string, cc *encconfig.CryptoConfig, layers []int32, platformList []string) (images.Image, error) {
	return cryptImage(client, ctx, name, newName, cc, layers, platformList, true)
}

func decryptImage(client *containerd.Client, ctx gocontext.Context, name, newName string, cc *encconfig.CryptoConfig, layers []int32, platformList []string) (images.Image, error) {
	return cryptImage(client, ctx, name, newName, cc, layers, platformList, false)
}
func getImageLayerInfo(client *containerd.Client, ctx gocontext.Context, name string, layers []int32, platformList []string) ([]encryption.LayerInfo, error) {
	s := client.ImageService()

	image, err := s.Get(ctx, name)
	if err != nil {
		return []encryption.LayerInfo{}, err
	}

	pl, err := platforms.ParseArray(platformList)
	if err != nil {
		return []encryption.LayerInfo{}, err
	}
	lf := &encryption.LayerFilter{
		Layers:    layers,
		Platforms: pl,
	}

	return images.GetImageLayerInfo(ctx, client.ContentStore(), image.Target, lf, -1)
}
