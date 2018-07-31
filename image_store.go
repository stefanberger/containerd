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

	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	ptypes "github.com/gogo/protobuf/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type remoteImages struct {
	client imagesapi.ImagesClient
}

// NewImageStoreFromClient returns a new image store client
func NewImageStoreFromClient(client imagesapi.ImagesClient) images.Store {
	return &remoteImages{
		client: client,
	}
}

func (s *remoteImages) Get(ctx context.Context, name string) (images.Image, error) {
	resp, err := s.client.Get(ctx, &imagesapi.GetImageRequest{
		Name: name,
	})
	if err != nil {
		return images.Image{}, errdefs.FromGRPC(err)
	}

	return imageFromProto(resp.Image), nil
}

func (s *remoteImages) List(ctx context.Context, filters ...string) ([]images.Image, error) {
	resp, err := s.client.List(ctx, &imagesapi.ListImagesRequest{
		Filters: filters,
	})
	if err != nil {
		return nil, errdefs.FromGRPC(err)
	}

	return imagesFromProto(resp.Images), nil
}

func (s *remoteImages) Create(ctx context.Context, image images.Image) (images.Image, error) {
	created, err := s.client.Create(ctx, &imagesapi.CreateImageRequest{
		Image: imageToProto(&image),
	})
	if err != nil {
		return images.Image{}, errdefs.FromGRPC(err)
	}

	return imageFromProto(&created.Image), nil
}

func (s *remoteImages) Update(ctx context.Context, image images.Image, fieldpaths ...string) (images.Image, error) {
	var updateMask *ptypes.FieldMask
	if len(fieldpaths) > 0 {
		updateMask = &ptypes.FieldMask{
			Paths: fieldpaths,
		}
	}

	updated, err := s.client.Update(ctx, &imagesapi.UpdateImageRequest{
		Image:      imageToProto(&image),
		UpdateMask: updateMask,
	})
	if err != nil {
		return images.Image{}, errdefs.FromGRPC(err)
	}

	return imageFromProto(&updated.Image), nil
}

func (s *remoteImages) Delete(ctx context.Context, name string, opts ...images.DeleteOpt) error {
	var do images.DeleteOptions
	for _, opt := range opts {
		if err := opt(ctx, &do); err != nil {
			return err
		}
	}
	_, err := s.client.Delete(ctx, &imagesapi.DeleteImageRequest{
		Name: name,
		Sync: do.Synchronous,
	})

	return errdefs.FromGRPC(err)
}

func imageToProto(image *images.Image) imagesapi.Image {
	return imagesapi.Image{
		Name:      image.Name,
		Labels:    image.Labels,
		Target:    descToProto(&image.Target),
		CreatedAt: image.CreatedAt,
		UpdatedAt: image.UpdatedAt,
	}
}

func imageFromProto(imagepb *imagesapi.Image) images.Image {
	return images.Image{
		Name:      imagepb.Name,
		Labels:    imagepb.Labels,
		Target:    descFromProto(&imagepb.Target),
		CreatedAt: imagepb.CreatedAt,
		UpdatedAt: imagepb.UpdatedAt,
	}
}

func (s *remoteImages) EncryptImage(ctx context.Context, name, newName string, cc *images.CryptoConfig, layers []int32, platforms []string) (images.Image, error) {
	layerSymKeyMap := convLayerSymKeyMap(cc.Ec.Dc.LayerSymKeyMap)

	resp, err := s.client.EncryptImage(ctx, &imagesapi.EncryptImageRequest{
		Name:    name,
		NewName: newName,
		Ec: &imagesapi.EncryptConfig{
			Recipients:    cc.Ec.Recipients,
			Gpgpubkeyring: cc.Ec.GPGPubRingFile,
			Operation:     cc.Ec.Operation,
			Dc: &imagesapi.DecryptConfig{
				LayerSymKeyMap: layerSymKeyMap,
			},
		},
		Layers:    layers,
		Platforms: platforms,
	})
	if err != nil {
		return images.Image{}, errdefs.FromGRPC(err)
	}

	return imageFromProto(&resp.Image), nil
}

func (s *remoteImages) DecryptImage(ctx context.Context, name, newName string, cc *images.CryptoConfig, layers []int32, platforms []string) (images.Image, error) {
	layerSymKeyMap := convLayerSymKeyMap(cc.Dc.LayerSymKeyMap)

	resp, err := s.client.DecryptImage(ctx, &imagesapi.DecryptImageRequest{
		Name:    name,
		NewName: newName,
		Dc: &imagesapi.DecryptConfig{
			LayerSymKeyMap: layerSymKeyMap,
		},
		Layers:    layers,
		Platforms: platforms,
	})
	if err != nil {
		return images.Image{}, errdefs.FromGRPC(err)
	}

	return imageFromProto(&resp.Image), nil
}

func (s *remoteImages) GetImageLayerInfo(ctx context.Context, name string, layers []int32, platforms []string) ([]images.LayerInfo, error) {
	resp, err := s.client.GetImageLayerInfo(ctx, &imagesapi.GetImageLayerInfoRequest{
		Name:      name,
		Layers:    layers,
		Platforms: platforms,
	})
	if err != nil {
		return []images.LayerInfo{}, errdefs.FromGRPC(err)
	}

	li := make([]images.LayerInfo, len(resp.LayerInfo))
	for i := 0; i < len(resp.LayerInfo); i++ {
		li[i].ID = resp.LayerInfo[i].ID
		li[i].WrappedKeys = resp.LayerInfo[i].WrappedKeys
		li[i].Digest = resp.LayerInfo[i].Digest
		li[i].Encryption = resp.LayerInfo[i].Encryption
		li[i].FileSize = resp.LayerInfo[i].FileSize
		li[i].Platform = resp.LayerInfo[i].Platform
	}

	return li, nil
}

func convLayerSymKeyMap(layerSymKeyMap map[string]images.DecryptKeyData) map[string]*imagesapi.DecryptKeyData {
	layerSymKeyMapOut := make(map[string]*imagesapi.DecryptKeyData)

	for k, v := range layerSymKeyMap {
		layerSymKeyMapOut[k] = &imagesapi.DecryptKeyData{
			SymKeyData:   v.SymKeyData,
			SymKeyCipher: uint32(v.SymKeyCipher),
		}
	}
	return layerSymKeyMapOut
}

func imagesFromProto(imagespb []imagesapi.Image) []images.Image {
	var images []images.Image

	for _, image := range imagespb {
		images = append(images, imageFromProto(&image))
	}

	return images
}

func descFromProto(desc *types.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Size:      desc.Size_,
		Digest:    desc.Digest,
	}
}

func descToProto(desc *ocispec.Descriptor) types.Descriptor {
	return types.Descriptor{
		MediaType: desc.MediaType,
		Size_:     desc.Size,
		Digest:    desc.Digest,
	}
}
