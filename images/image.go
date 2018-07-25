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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Image provides the model for how containerd views container images.
type Image struct {
	// Name of the image.
	//
	// To be pulled, it must be a reference compatible with resolvers.
	//
	// This field is required.
	Name string

	// Labels provide runtime decoration for the image record.
	//
	// There is no default behavior for how these labels are propagated. They
	// only decorate the static metadata object.
	//
	// This field is optional.
	Labels map[string]string

	// Target describes the root content for this image. Typically, this is
	// a manifest, index or manifest list.
	Target ocispec.Descriptor

	CreatedAt, UpdatedAt time.Time
}

type LayerInfo struct {
	// The Id of the layer starting at 0
	Id uint32
	// An array of KeyIds to which the layer is encrypted
	KeyIds []uint64
	// The Digest of the layer
	Digest string
	// The Encryption algorithm used for encrypting the layer
	Encryption string
	// The size of the layer file
	FileSize int64
	// The platform for which this layer is
	Platform string
}

// DeleteOptions provide options on image delete
type DeleteOptions struct {
	Synchronous bool
}

// DeleteOpt allows configuring a delete operation
type DeleteOpt func(context.Context, *DeleteOptions) error

// SynchronousDelete is used to indicate that an image deletion and removal of
// the image resources should occur synchronously before returning a result.
func SynchronousDelete() DeleteOpt {
	return func(ctx context.Context, o *DeleteOptions) error {
		o.Synchronous = true
		return nil
	}
}

// Store and interact with images
type Store interface {
	Get(ctx context.Context, name string) (Image, error)
	List(ctx context.Context, filters ...string) ([]Image, error)
	Create(ctx context.Context, image Image) (Image, error)

	// Update will replace the data in the store with the provided image. If
	// one or more fieldpaths are provided, only those fields will be updated.
	Update(ctx context.Context, image Image, fieldpaths ...string) (Image, error)

	Delete(ctx context.Context, name string, opts ...DeleteOpt) error

	EncryptImage(ctx context.Context, name, newName string, ec *CryptoConfig, layers []int) (Image, error)
	DecryptImage(ctx context.Context, name, newName string, ec *CryptoConfig, layers []int) (Image, error)
	GetImageLayerInfo(ctx context.Context, name string, layers []int) ([]LayerInfo, error)
}

// TODO(stevvooe): Many of these functions make strong platform assumptions,
// which are untrue in a lot of cases. More refactoring must be done here to
// make this work in all cases.

// Config resolves the image configuration descriptor.
//
// The caller can then use the descriptor to resolve and process the
// configuration of the image.
func (image *Image) Config(ctx context.Context, provider content.Provider, platform string) (ocispec.Descriptor, error) {
	return Config(ctx, provider, image.Target, platform)
}

// RootFS returns the unpacked diffids that make up and images rootfs.
//
// These are used to verify that a set of layers unpacked to the expected
// values.
func (image *Image) RootFS(ctx context.Context, provider content.Provider, platform string) ([]digest.Digest, error) {
	desc, err := image.Config(ctx, provider, platform)
	if err != nil {
		return nil, err
	}
	return RootFS(ctx, provider, desc)
}

// Size returns the total size of an image's packed resources.
func (image *Image) Size(ctx context.Context, provider content.Provider, platform string) (int64, error) {
	var size int64
	return size, Walk(ctx, Handlers(HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.Size < 0 {
			return nil, errors.Errorf("invalid size %v in %v (%v)", desc.Size, desc.Digest, desc.MediaType)
		}
		size += desc.Size
		return nil, nil
	}), FilterPlatforms(ChildrenHandler(provider), platform)), image.Target)
}

// Manifest resolves a manifest from the image for the given platform.
//
// TODO(stevvooe): This violates the current platform agnostic approach to this
// package by returning a specific manifest type. We'll need to refactor this
// to return a manifest descriptor or decide that we want to bring the API in
// this direction because this abstraction is not needed.`
func Manifest(ctx context.Context, provider content.Provider, image ocispec.Descriptor, platform string) (ocispec.Manifest, error) {
	var (
		matcher  platforms.Matcher
		m        *ocispec.Manifest
		p        ocispec.Platform
		wasIndex bool
	)
	if platform != "" {
		var err error
		p, err = platforms.Parse(platform)
		if err != nil {
			return ocispec.Manifest{}, err
		}
		matcher = platforms.NewMatcher(p)
	}

	if err := Walk(ctx, HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch desc.MediaType {
		case MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
			p, err := content.ReadBlob(ctx, provider, desc)
			if err != nil {
				return nil, err
			}

			var manifest ocispec.Manifest
			if err := json.Unmarshal(p, &manifest); err != nil {
				return nil, err
			}

			if platform != "" {
				if desc.Platform != nil && !matcher.Match(*desc.Platform) {
					return nil, nil
				}

				if desc.Platform == nil {
					p, err := content.ReadBlob(ctx, provider, manifest.Config)
					if err != nil {
						return nil, err
					}

					var image ocispec.Image
					if err := json.Unmarshal(p, &image); err != nil {
						return nil, err
					}

					if !matcher.Match(platforms.Normalize(ocispec.Platform{OS: image.OS, Architecture: image.Architecture})) {
						return nil, nil
					}

				}
			}

			m = &manifest

			return nil, nil
		case MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
			p, err := content.ReadBlob(ctx, provider, desc)
			if err != nil {
				return nil, err
			}

			var idx ocispec.Index
			if err := json.Unmarshal(p, &idx); err != nil {
				return nil, err
			}

			if platform == "" {
				return idx.Manifests, nil
			}

			var descs []ocispec.Descriptor
			for _, d := range idx.Manifests {
				if d.Platform == nil || matcher.Match(*d.Platform) {
					descs = append(descs, d)
				}
			}

			wasIndex = true

			return descs, nil

		}
		return nil, errors.Wrapf(errdefs.ErrNotFound, "unexpected media type %v for %v", desc.MediaType, desc.Digest)
	}), image); err != nil {
		return ocispec.Manifest{}, err
	}

	if m == nil {
		err := errors.Wrapf(errdefs.ErrNotFound, "manifest %v", image.Digest)
		if wasIndex {
			err = errors.Wrapf(errdefs.ErrNotFound, "no match for current platform %s in manifest %v", platforms.Format(p), image.Digest)
		}
		return ocispec.Manifest{}, err
	}

	return *m, nil
}

// Config resolves the image configuration descriptor using a content provided
// to resolve child resources on the image.
//
// The caller can then use the descriptor to resolve and process the
// configuration of the image.
func Config(ctx context.Context, provider content.Provider, image ocispec.Descriptor, platform string) (ocispec.Descriptor, error) {
	manifest, err := Manifest(ctx, provider, image, platform)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return manifest.Config, err
}

// Platforms returns one or more platforms supported by the image.
func Platforms(ctx context.Context, provider content.Provider, image ocispec.Descriptor) ([]ocispec.Platform, error) {
	var platformSpecs []ocispec.Platform
	return platformSpecs, Walk(ctx, Handlers(HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.Platform != nil {
			platformSpecs = append(platformSpecs, *desc.Platform)
			return nil, ErrSkipDesc
		}

		switch desc.MediaType {
		case MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig:
			p, err := content.ReadBlob(ctx, provider, desc)
			if err != nil {
				return nil, err
			}

			var image ocispec.Image
			if err := json.Unmarshal(p, &image); err != nil {
				return nil, err
			}

			platformSpecs = append(platformSpecs,
				platforms.Normalize(ocispec.Platform{OS: image.OS, Architecture: image.Architecture}))
		}
		return nil, nil
	}), ChildrenHandler(provider)), image)
}

// Check returns nil if the all components of an image are available in the
// provider for the specified platform.
//
// If available is true, the caller can assume that required represents the
// complete set of content required for the image.
//
// missing will have the components that are part of required but not avaiiable
// in the provider.
//
// If there is a problem resolving content, an error will be returned.
func Check(ctx context.Context, provider content.Provider, image ocispec.Descriptor, platform string) (available bool, required, present, missing []ocispec.Descriptor, err error) {
	mfst, err := Manifest(ctx, provider, image, platform)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return false, []ocispec.Descriptor{image}, nil, []ocispec.Descriptor{image}, nil
		}

		return false, nil, nil, nil, errors.Wrapf(err, "failed to check image %v", image.Digest)
	}

	// TODO(stevvooe): It is possible that referenced conponents could have
	// children, but this is rare. For now, we ignore this and only verify
	// that manifest components are present.
	required = append([]ocispec.Descriptor{mfst.Config}, mfst.Layers...)

	for _, desc := range required {
		ra, err := provider.ReaderAt(ctx, desc)
		if err != nil {
			if errdefs.IsNotFound(err) {
				missing = append(missing, desc)
				continue
			} else {
				return false, nil, nil, nil, errors.Wrapf(err, "failed to check image %v", desc.Digest)
			}
		}
		ra.Close()
		present = append(present, desc)

	}

	return true, required, present, missing, nil
}

// encryptLayer encryts a single layer and writes the encrypted layer back into storage
func cryptLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *CryptoConfig, encrypt bool) (ocispec.Descriptor, error) {
	data, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	//fmt.Printf("   ... read %d bytes of layer %s data\n", len(p), desc.Digest)
	// now we should encrypt

	var p []byte
	var keys [][]byte
	if encrypt {
		p, keys, err = Encrypt(cc, data)
	} else {
		p, err = Decrypt(cc, data, desc)
	}
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	size := int64(len(p))
	d := digest.FromBytes(p)

	newDesc := ocispec.Descriptor{
		Digest:   d,
		Size:     size,
		Platform: desc.Platform,
	}
	if encrypt {
		newDesc.Annotations = make(map[string]string)
		newDesc.Annotations["org.opencontainers.image.pgp.keys"] = encodeWrappedKeys(keys)
	}

	switch desc.MediaType {
	case MediaTypeDockerSchema2LayerGzip:
		newDesc.MediaType = MediaTypeDockerSchema2LayerGzipPGP
	case MediaTypeDockerSchema2Layer:
		newDesc.MediaType = MediaTypeDockerSchema2LayerPGP
	case MediaTypeDockerSchema2LayerGzipPGP:
		newDesc.MediaType = MediaTypeDockerSchema2LayerGzip
	case MediaTypeDockerSchema2LayerPGP:
		newDesc.MediaType = MediaTypeDockerSchema2Layer
	default:
		return ocispec.Descriptor{}, errors.Wrapf(err, "Unsupporter layer MediaType: %s\n", desc.MediaType)
	}

	ref := fmt.Sprintf("layer-%s", newDesc.Digest.String())
	content.WriteBlob(ctx, cs, ref, bytes.NewReader(p), newDesc)

	return newDesc, nil
}
func getWrappedKeys(desc ocispec.Descriptor) ([][]byte, error) {
	// Parse and decode keys
	if v, ok := desc.Annotations["org.opencontainers.image.pgp.keys"]; ok {
		keys, err := decodeWrappedKeys(v)
		if err != nil {
			return nil, err
		}
		return keys, nil
	} else {
		return make([][]byte, 0), nil
	}
}

// assembleEncryptedMessage takes in the openpgp encrypted body packets and
// assembles the openpgp message
func assembleEncryptedMessage(encBody []byte, keys [][]byte) []byte {
	encMsg := make([]byte, 0)

	for _, k := range keys {
		encMsg = append(encMsg, k...)
	}
	encMsg = append(encMsg, encBody...)

	return encMsg
}

// encodeWrappedKeys encodes wrapped openpgp keys to a string readable ','
// separated base64 strings.
func encodeWrappedKeys(keys [][]byte) string {
	keyString := ""
	for _, k := range keys {
		if keyString == "" {
			keyString += base64.StdEncoding.EncodeToString(k)
		} else {
			keyString += "," + base64.StdEncoding.EncodeToString(k)
		}
	}

	return keyString
}

// decodeWrappedKeys decodes wrapped openpgp keys from string readable ','
// separated base64 strings to their byte values
func decodeWrappedKeys(keys string) ([][]byte, error) {
	kSplit := strings.Split(keys, ",")
	keyBytes := make([][]byte, 0, len(kSplit))

	for _, v := range kSplit {
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		keyBytes = append(keyBytes, data)
	}

	return keyBytes, nil
}

// isDecriptorALayer determines whether the given Descriptor describes a layer
func isDescriptorALayer(desc ocispec.Descriptor) bool {
	switch desc.MediaType {
	case MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2Layer,
		MediaTypeDockerSchema2LayerGzipPGP, MediaTypeDockerSchema2LayerPGP:
		return true
	}
	return false
}

// countLayers counts the number of layer OCI descriptors in the given array
func countLayers(desc []ocispec.Descriptor) int {
	c := 0

	for _, d := range desc {
		if isDescriptorALayer(d) {
			c = c + 1
		}
	}
	return c
}

// needModifyLayer checks whether we need to modify this layer given its number
// A layer can be described with its (positive) index number or its negative number, which
// is counted relative to the last one
func isUserSelectedLayer(layerNum, layersTotal int, layers []int) bool {
	if len(layers) == 0 {
		// convenience for the user; none given means 'all'
		return true
	}
	negNumber := layerNum - layersTotal
	fmt.Printf("%d vs %d\n", layerNum, negNumber)

	for _, l := range layers {
		if l == negNumber || l == layerNum {
			return true
		}
	}
	return false
}

// Encrypt all the Children of a given descriptor
func cryptChildren(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *CryptoConfig, layers []int, encrypt bool) (ocispec.Descriptor, bool, error) {
	layerNum := 0

	children, err := Children(ctx, cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}

	layersTotal := countLayers(children)

	//fmt.Printf("metadata/image.go EncryptChildren(): got %d children\n", len(children))
	var newLayers []ocispec.Descriptor
	var config ocispec.Descriptor
	modified := false

	for _, child := range children {
		// we only encrypt child layers and have to update their parents if encyrption happened
		switch child.MediaType {
		case MediaTypeDockerSchema2Config:
			config = child
		case MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2Layer:
			// this one we can only encrypt
			if encrypt && isUserSelectedLayer(layerNum, layersTotal, layers) {
				nl, err := cryptLayer(ctx, cs, child, cc, true)
				if err != nil {
					return ocispec.Descriptor{}, false, err
				}
				modified = true
				newLayers = append(newLayers, nl)
			} else {
				newLayers = append(newLayers, child)
			}
			layerNum = layerNum + 1
		case MediaTypeDockerSchema2LayerGzipPGP, MediaTypeDockerSchema2LayerPGP:
			// this one we can only decrypt
			if !encrypt && isUserSelectedLayer(layerNum, layersTotal, layers) {
				nl, err := cryptLayer(ctx, cs, child, cc, false)
				if err != nil {
					return ocispec.Descriptor{}, false, err
				}
				modified = true
				newLayers = append(newLayers, nl)
			} else {
				newLayers = append(newLayers, child)
			}
			layerNum = layerNum + 1
		default:
			return ocispec.Descriptor{}, false, errors.Wrapf(err, "Bad/unhandled MediaType %s in encryptChildren\n", child.MediaType)
		}
	}

	if modified && len(newLayers) > 0 {
		nM := ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: config,
			Layers: newLayers,
		}

		mb, err := json.MarshalIndent(nM, "", "   ")
		if err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to marshal image")
		}

		nDesc := ocispec.Descriptor{
			MediaType: MediaTypeDockerSchema2Manifest, //ocispec.MediaTypeImageManifest,//MediaTypeDockerSchema2Manifest,
			Size:      int64(len(mb)),
			Digest:    digest.Canonical.FromBytes(mb),
			Platform:  desc.Platform,
		}
		labels := map[string]string{}
		labels["containerd.io/gc.ref.content.0"] = nM.Config.Digest.String()
		for i, ch := range nM.Layers {
			labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i+1)] = ch.Digest.String()
		}

		fmt.Printf("   old desc %s now written as %s\n", desc.Digest, nDesc.Digest)

		ref := fmt.Sprintf("manifest-%s", nDesc.Digest.String())
		//, content.WithLabels(labels)
		if err := content.WriteBlob(ctx, cs, ref, bytes.NewReader(mb), nDesc, content.WithLabels(labels)); err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to write config")
		}
		return nDesc, true, nil
	}

	return desc, modified, nil
}

// cryptManifestList encrypts or decrypts the children of a top level manifest list
func CryptManifestList(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *CryptoConfig, layers []int, encrypt bool) (ocispec.Descriptor, bool, error) {
	if desc.MediaType != MediaTypeDockerSchema2ManifestList {
		return ocispec.Descriptor{}, false, errors.Wrapf(nil, "Wrong media type %s passed. Need %s.\n", desc.MediaType, MediaTypeDockerSchema2ManifestList)
	}
	// read the index; if any layer is encrypted and any manifests change we will need to rewrite it
	b, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}

	var index ocispec.Index
	if err := json.Unmarshal(b, &index); err != nil {
		return ocispec.Descriptor{}, false, err
	}

	var newManifests []ocispec.Descriptor
	modified := false
	for _, manifest := range index.Manifests {
		newManifest, m, err := cryptChildren(ctx, cs, manifest, cc, layers, encrypt)
		if err != nil {
			return ocispec.Descriptor{}, false, err
		}
		newManifests = append(newManifests, newManifest)
		if m {
			modified = true
		}
	}

	if modified {
		// we need to update the index
		newIndex := ocispec.Index{
			Versioned: index.Versioned,
			Manifests: newManifests,
		}
		mb, err := json.MarshalIndent(newIndex, "", "   ")
		if err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to marshal index")
		}

		nDesc := ocispec.Descriptor{
			MediaType: desc.MediaType,
			Size:      int64(len(mb)),
			Digest:    digest.Canonical.FromBytes(mb),
		}
		fmt.Printf("   old Index %s now written as %s\n", desc.Digest, nDesc.Digest)

		labels := map[string]string{}
		for i, m := range newIndex.Manifests {
			labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i)] = m.Digest.String()
		}

		ref := fmt.Sprintf("index-%s", nDesc.Digest.String())
		if err := content.WriteBlob(ctx, cs, ref, bytes.NewReader(mb), nDesc, content.WithLabels(labels)); err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to write index")
		}
		return nDesc, true, nil
	}

	return desc, false, nil
}

// Get the image key Ids necessary for decrypting an image
// We determine the KeyIds starting with  the given OCI Decriptor, recursing to lower-level descriptors
// until we get them from the layer descriptors
func GetImageLayerInfo(ctx context.Context, cs content.Store, desc ocispec.Descriptor, layers []int, layerNum int) ([]LayerInfo, error) {
	var (
		lis      []LayerInfo
		tmp      []LayerInfo
		Platform string
	)

	switch desc.MediaType {
	case MediaTypeDockerSchema2ManifestList,
		MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		children, err := Children(ctx, cs, desc)
		if desc.Platform != nil {
			Platform = desc.Platform.OS + "/" + desc.Platform.Architecture
			if desc.Platform.Variant != "" {
				Platform = Platform + "/" + desc.Platform.Variant
			}
		}
		if err != nil {
			return []LayerInfo{}, err
		}

		layersTotal := countLayers(children)
		layerNum := -1

		for _, child := range children {
			if isDescriptorALayer(child) {
				layerNum = layerNum + 1
				if isUserSelectedLayer(layerNum, layersTotal, layers) {
					tmp, err = GetImageLayerInfo(ctx, cs, child, layers, layerNum)
				} else {
					continue
				}
			} else {
				tmp, err = GetImageLayerInfo(ctx, cs, child, layers, -1)
			}
			if err != nil {
				return []LayerInfo{}, err
			}

			for i := 0; i < len(tmp); i++ {
				if Platform != "" {
					tmp[i].Platform = Platform
				}
			}
			lis = append(lis, tmp...)
		}
	case MediaTypeDockerSchema2Layer, MediaTypeDockerSchema2LayerGzip:
		li := LayerInfo{
			KeyIds:     []uint64{},
			Digest:     desc.Digest.String(),
			Encryption: "",
			FileSize:   desc.Size,
			Id:         uint32(layerNum),
		}
		lis = append(lis, li)
	case MediaTypeDockerSchema2Config:
	case MediaTypeDockerSchema2LayerPGP, MediaTypeDockerSchema2LayerGzipPGP:
		kids, err := GetKeyIds(desc)
		if err != nil {
			return []LayerInfo{}, err
		}
		li := LayerInfo{
			KeyIds:     kids,
			Digest:     desc.Digest.String(),
			Encryption: "gpg",
			FileSize:   desc.Size,
			Id:         uint32(layerNum),
		}
		lis = append(lis, li)
	default:
		return []LayerInfo{}, errors.Wrapf(nil, "GetImageLayerInfo: Unhandled media type %s", desc.MediaType)
	}

	return lis, nil
}

// Children returns the immediate children of content described by the descriptor.
func Children(ctx context.Context, provider content.Provider, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var descs []ocispec.Descriptor
	switch desc.MediaType {
	case MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		p, err := content.ReadBlob(ctx, provider, desc)
		if err != nil {
			return nil, err
		}

		// TODO(stevvooe): We just assume oci manifest, for now. There may be
		// subtle differences from the docker version.
		var manifest ocispec.Manifest
		if err := json.Unmarshal(p, &manifest); err != nil {
			return nil, err
		}

		descs = append(descs, manifest.Config)
		descs = append(descs, manifest.Layers...)
	case MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		p, err := content.ReadBlob(ctx, provider, desc)
		if err != nil {
			return nil, err
		}

		var index ocispec.Index
		if err := json.Unmarshal(p, &index); err != nil {
			return nil, err
		}

		descs = append(descs, index.Manifests...)
	case MediaTypeDockerSchema2Layer, MediaTypeDockerSchema2LayerGzip,
		MediaTypeDockerSchema2LayerPGP, MediaTypeDockerSchema2LayerGzipPGP,
		MediaTypeDockerSchema2LayerForeign, MediaTypeDockerSchema2LayerForeignGzip,
		MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig,
		ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageLayerGzip,
		ocispec.MediaTypeImageLayerNonDistributable, ocispec.MediaTypeImageLayerNonDistributableGzip,
		MediaTypeContainerd1Checkpoint, MediaTypeContainerd1CheckpointConfig:
		// childless data types.
		return nil, nil
	default:
		log.G(ctx).Warnf("encountered unknown type %v; children may not be fetched", desc.MediaType)
	}

	return descs, nil
}

// RootFS returns the unpacked diffids that make up and images rootfs.
//
// These are used to verify that a set of layers unpacked to the expected
// values.
func RootFS(ctx context.Context, provider content.Provider, configDesc ocispec.Descriptor) ([]digest.Digest, error) {
	p, err := content.ReadBlob(ctx, provider, configDesc)
	if err != nil {
		return nil, err
	}

	var config ocispec.Image
	if err := json.Unmarshal(p, &config); err != nil {
		return nil, err
	}
	return config.RootFS.DiffIDs, nil
}

// IsCompressedDiff returns true if mediaType is a known compressed diff media type.
// It returns false if the media type is a diff, but not compressed. If the media type
// is not a known diff type, it returns errdefs.ErrNotImplemented
func IsCompressedDiff(ctx context.Context, mediaType string) (bool, error) {
	switch mediaType {
	case ocispec.MediaTypeImageLayer, MediaTypeDockerSchema2Layer:
	case ocispec.MediaTypeImageLayerGzip, MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2LayerGzipPGP:
		return true, nil
	default:
		// Still apply all generic media types *.tar[.+]gzip and *.tar
		if strings.HasSuffix(mediaType, ".tar.gzip") || strings.HasSuffix(mediaType, ".tar+gzip") {
			return true, nil
		} else if !strings.HasSuffix(mediaType, ".tar") {
			return false, errdefs.ErrNotImplemented
		}
	}
	return false, nil
}
