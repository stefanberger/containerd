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

package containerd

import (
	"context"
	"runtime"
	"testing"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/encryption"
	encconfig "github.com/containerd/containerd/images/encryption/config"
	"github.com/containerd/containerd/images/encryption/utils"
	"github.com/containerd/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func setupBusyboxImage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}

	const imageName = "docker.io/library/busybox:latest"
	ctx, cancel := testContext()
	defer cancel()

	client, err := newClient(t, address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Cleanup
	err = client.ImageService().Delete(ctx, imageName)
	if err != nil && !errdefs.IsNotFound(err) {
		t.Fatal(err)
	}

	// By default pull does not unpack an image
	image, err := client.Pull(ctx, imageName, WithPlatform("linux/amd64"))
	if err != nil {
		t.Fatal(err)
	}

	err = image.Unpack(ctx, DefaultSnapshotter)
	if err != nil {
		t.Fatal(err)
	}
}

func TestImageEncryption(t *testing.T) {
	setupBusyboxImage(t)

	publicKey, privateKey, err := utils.CreateRSATestKey(2048, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	const imageName = "docker.io/library/busybox:latest"
	ctx, cancel := testContext()
	defer cancel()

	client, err := newClient(t, address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	s := client.ImageService()

	image, err := s.Get(ctx, imageName)
	if err != nil {
		t.Fatal(err)
	}

	pl, err := platforms.ParseArray([]string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}

	lf := &encryption.LayerFilter{
		Layers:    []int32{},
		Platforms: pl,
	}

	dcparameters := make(map[string][][]byte)
	parameters := make(map[string][][]byte)

	parameters["pubkeys"] = [][]byte{publicKey}
	dcparameters["privkeys"] = [][]byte{privateKey}
	dcparameters["privkeys-passwords"] = [][]byte{{}}

	cc := &encconfig.CryptoConfig{
		EncryptConfig: &encconfig.EncryptConfig{
			Parameters: parameters,
			DecryptConfig: encconfig.DecryptConfig{
				Parameters: dcparameters,
			},
		},
	}

	// Perform encryption of image
	encSpec, modified, err := images.EncryptImage(ctx, client.ContentStore(), image.Target, cc, lf)
	if err != nil {
		t.Fatal(err)
	}
	if !modified || image.Target.Digest == encSpec.Digest {
		t.Fatal("Encryption did not modify the spec")
	}

	if !hasEncryption(ctx, client.ContentStore(), encSpec) {
		t.Fatal("Encrypted image does not have encrypted layers")
	}

	cc = &encconfig.CryptoConfig{
		DecryptConfig: &encconfig.DecryptConfig{
			Parameters: dcparameters,
		},
	}

	// Perform decryption of image
	defer client.ImageService().Delete(ctx, imageName, images.SynchronousDelete())
	decSpec, modified, err := images.DecryptImage(ctx, client.ContentStore(), encSpec, cc, lf)
	if err != nil {
		t.Fatal(err)
	}
	if !modified || encSpec.Digest == decSpec.Digest {
		t.Fatal("Decryption did not modify the spec")
	}

	if hasEncryption(ctx, client.ContentStore(), decSpec) {
		t.Fatal("Decrypted image has encrypted layers")
	}
}

func hasEncryption(ctx context.Context, provider content.Provider, spec ocispec.Descriptor) bool {
	switch spec.MediaType {
	case images.MediaTypeDockerSchema2LayerEnc, images.MediaTypeDockerSchema2LayerGzipEnc:
		return true
	default:
		// pass
	}
	cspecs, err := images.Children(ctx, provider, spec)
	if err != nil {
		return false
	}

	for _, v := range cspecs {
		if hasEncryption(ctx, provider, v) {
			return true
		}
	}

	return false
}
