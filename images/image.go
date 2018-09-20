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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images/encryption"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/rootfs"
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

	EncryptImage(ctx context.Context, name, newName string, ec *encryption.CryptoConfig, layers []int32, platforms []string) (Image, error)
	DecryptImage(ctx context.Context, name, newName string, ec *encryption.CryptoConfig, layers []int32, platforms []string) (Image, error)
	GetImageLayerInfo(ctx context.Context, name string, layers []int32, platforms []string) ([]encryption.LayerInfo, error)
}

// TODO(stevvooe): Many of these functions make strong platform assumptions,
// which are untrue in a lot of cases. More refactoring must be done here to
// make this work in all cases.

// Config resolves the image configuration descriptor.
//
// The caller can then use the descriptor to resolve and process the
// configuration of the image.
func (image *Image) Config(ctx context.Context, provider content.Provider, platform platforms.MatchComparer) (ocispec.Descriptor, error) {
	return Config(ctx, provider, image.Target, platform)
}

// RootFS returns the unpacked diffids that make up and images rootfs.
//
// These are used to verify that a set of layers unpacked to the expected
// values.
func (image *Image) RootFS(ctx context.Context, provider content.Provider, platform platforms.MatchComparer) ([]digest.Digest, error) {
	desc, err := image.Config(ctx, provider, platform)
	if err != nil {
		return nil, err
	}
	return RootFS(ctx, provider, desc)
}

// Size returns the total size of an image's packed resources.
func (image *Image) Size(ctx context.Context, provider content.Provider, platform platforms.MatchComparer) (int64, error) {
	var size int64
	return size, Walk(ctx, Handlers(HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.Size < 0 {
			return nil, errors.Errorf("invalid size %v in %v (%v)", desc.Size, desc.Digest, desc.MediaType)
		}
		size += desc.Size
		return nil, nil
	}), FilterPlatforms(ChildrenHandler(provider), platform)), image.Target)
}

type platformManifest struct {
	p *ocispec.Platform
	m *ocispec.Manifest
}

// Manifest resolves a manifest from the image for the given platform.
//
// When a manifest descriptor inside of a manifest index does not have
// a platform defined, the platform from the image config is considered.
//
// If the descriptor points to a non-index manifest, then the manifest is
// unmarshalled and returned without considering the platform inside of the
// config.
//
// TODO(stevvooe): This violates the current platform agnostic approach to this
// package by returning a specific manifest type. We'll need to refactor this
// to return a manifest descriptor or decide that we want to bring the API in
// this direction because this abstraction is not needed.`
func Manifest(ctx context.Context, provider content.Provider, image ocispec.Descriptor, platform platforms.MatchComparer) (ocispec.Manifest, error) {
	var (
		m        []platformManifest
		wasIndex bool
	)

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

			if desc.Digest != image.Digest && platform != nil {
				if desc.Platform != nil && !platform.Match(*desc.Platform) {
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

					if !platform.Match(platforms.Normalize(ocispec.Platform{OS: image.OS, Architecture: image.Architecture})) {
						return nil, nil
					}

				}
			}

			m = append(m, platformManifest{
				p: desc.Platform,
				m: &manifest,
			})

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

			if platform == nil {
				return idx.Manifests, nil
			}

			var descs []ocispec.Descriptor
			for _, d := range idx.Manifests {
				if d.Platform == nil || platform.Match(*d.Platform) {
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

	if len(m) == 0 {
		err := errors.Wrapf(errdefs.ErrNotFound, "manifest %v", image.Digest)
		if wasIndex {
			err = errors.Wrapf(errdefs.ErrNotFound, "no match for platform in manifest %v", image.Digest)
		}
		return ocispec.Manifest{}, err
	}

	sort.SliceStable(m, func(i, j int) bool {
		if m[i].p == nil {
			return false
		}
		if m[j].p == nil {
			return true
		}
		return platform.Less(*m[i].p, *m[j].p)
	})

	return *m[0].m, nil
}

// Config resolves the image configuration descriptor using a content provided
// to resolve child resources on the image.
//
// The caller can then use the descriptor to resolve and process the
// configuration of the image.
func Config(ctx context.Context, provider content.Provider, image ocispec.Descriptor, platform platforms.MatchComparer) (ocispec.Descriptor, error) {
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
func Check(ctx context.Context, provider content.Provider, image ocispec.Descriptor, platform platforms.MatchComparer) (available bool, required, present, missing []ocispec.Descriptor, err error) {
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
		MediaTypeDockerSchema2LayerEnc, MediaTypeDockerSchema2LayerGzipEnc,
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
	case ocispec.MediaTypeImageLayerGzip, MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2LayerGzipEnc:
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

// encryptLayer encrypts the layer using the CryptoConfig and creates a new OCI Descriptor.
// A call to this function may also only manipulate the wrapped keys list.
// The caller is expected to store the returned encrypted data and OCI Descriptor
func encryptLayer(cc *encryption.CryptoConfig, data []byte, desc ocispec.Descriptor) (ocispec.Descriptor, []byte, error) {
	var (
		wrappedKeys string
		size        int64
		d           digest.Digest
		err         error
	)

	p, wrappedKeys, annotationID, err := encryption.EncryptLayer(cc.Ec, data, desc)
	if err != nil {
		return ocispec.Descriptor{}, []byte{}, err
	}

	// were data touched ?
	if len(p) > 0 {
		size = int64(len(p))
		d = digest.FromBytes(p)
	} else {
		size = desc.Size
		d = desc.Digest
	}

	newDesc := ocispec.Descriptor{
		Digest:   d,
		Size:     size,
		Platform: desc.Platform,
	}
	newDesc.Annotations = make(map[string]string)
	newDesc.Annotations[annotationID] = wrappedKeys

	switch desc.MediaType {
	case MediaTypeDockerSchema2LayerGzip:
		newDesc.MediaType = MediaTypeDockerSchema2LayerGzipEnc
	case MediaTypeDockerSchema2Layer:
		newDesc.MediaType = MediaTypeDockerSchema2LayerEnc
	case MediaTypeDockerSchema2LayerGzipEnc:
		newDesc.MediaType = MediaTypeDockerSchema2LayerGzipEnc
	case MediaTypeDockerSchema2LayerEnc:
		newDesc.MediaType = MediaTypeDockerSchema2LayerEnc

		// TODO: Mediatypes to be added in ocispec
	case ocispec.MediaTypeImageLayerGzip:
		newDesc.MediaType = MediaTypeDockerSchema2LayerGzipEnc
	case ocispec.MediaTypeImageLayer:
		newDesc.MediaType = MediaTypeDockerSchema2LayerEnc

	default:
		return ocispec.Descriptor{}, []byte{}, errors.Errorf("Encryption: unsupporter layer MediaType: %s\n", desc.MediaType)
	}

	return newDesc, p, nil
}

// decryptLayer decrypts the layer using the CryptoConfig and creates a new OCI Descriptor.
// The caller is expected to store the returned plain data and OCI Descriptor
func decryptLayer(cc *encryption.CryptoConfig, data []byte, desc ocispec.Descriptor) (ocispec.Descriptor, []byte, error) {
	p, err := encryption.DecryptLayer(cc.Dc, data, desc)
	if err != nil {
		return ocispec.Descriptor{}, []byte{}, err
	}

	newDesc := ocispec.Descriptor{
		Digest:   digest.FromBytes(p),
		Size:     int64(len(p)),
		Platform: desc.Platform,
	}

	switch desc.MediaType {
	case MediaTypeDockerSchema2LayerGzipEnc:
		newDesc.MediaType = MediaTypeDockerSchema2LayerGzip
	case MediaTypeDockerSchema2LayerEnc:
		newDesc.MediaType = MediaTypeDockerSchema2Layer
	default:
		return ocispec.Descriptor{}, []byte{}, errors.Errorf("Decryption: unsupporter layer MediaType: %s\n", desc.MediaType)
	}
	return newDesc, p, nil
}

// cryptLayer handles the changes due to encryption or decryption of a layer
func cryptLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *encryption.CryptoConfig, encrypt bool) (ocispec.Descriptor, error) {
	var (
		p       []byte
		newDesc ocispec.Descriptor
	)

	data, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	if encrypt {
		newDesc, p, err = encryptLayer(cc, data, desc)
	} else {
		newDesc, p, err = decryptLayer(cc, data, desc)
	}
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	// some operations, such as changing recipients, may not touch the layer at all
	if len(p) > 0 {
		ref := fmt.Sprintf("layer-%s", newDesc.Digest.String())
		err = content.WriteBlob(ctx, cs, ref, bytes.NewReader(p), newDesc)
	}
	return newDesc, err
}

// isDecriptorALayer determines whether the given Descriptor describes an image layer
func isDescriptorALayer(desc ocispec.Descriptor) bool {
	switch desc.MediaType {
	case MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2Layer,
		MediaTypeDockerSchema2LayerGzipEnc, MediaTypeDockerSchema2LayerEnc:
		return true
	}
	return false
}

// countLayers counts the number of layer OCI descriptors in the given array
func countLayers(desc []ocispec.Descriptor) int32 {
	c := int32(0)

	for _, d := range desc {
		if isDescriptorALayer(d) {
			c = c + 1
		}
	}
	return c
}

// isUserSelectedLayer checks whether the a layer is user selected given its number
// A layer can be described with its (positive) index number or its negative number, which
// is counted relative to the topmost one (-1)
func isUserSelectedLayer(layerNum, layersTotal int32, layers []int32) bool {
	if len(layers) == 0 {
		// convenience for the user; none given means 'all'
		return true
	}
	negNumber := layerNum - layersTotal

	for _, l := range layers {
		if l == negNumber || l == layerNum {
			return true
		}
	}
	return false
}

// isUserSelectedPlatform determines whether the platform matches one in
// the array of user provided platforms
func isUserSelectedPlatform(platform *ocispec.Platform, platformList []ocispec.Platform) bool {
	if len(platformList) == 0 {
		// convenience for the user; none given means 'all'
		return true
	}
	matcher := platforms.NewMatcher(*platform)

	for _, platform := range platformList {
		if matcher.Match(platform) {
			return true
		}
	}
	return false
}

// Encrypt all the Children of a given descriptor
func cryptChildren(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *encryption.CryptoConfig, lf *encryption.LayerFilter, encrypt bool, thisPlatform *ocispec.Platform) (ocispec.Descriptor, bool, error) {
	layerNum := int32(0)

	children, err := Children(ctx, cs, desc)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return desc, false, nil
		}
		return ocispec.Descriptor{}, false, err
	}

	layersTotal := countLayers(children)

	var newLayers []ocispec.Descriptor
	var config ocispec.Descriptor
	modified := false

	for _, child := range children {
		// we only encrypt child layers and have to update their parents if encyrption happened
		switch child.MediaType {
		case MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig:
			config = child
		case MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2Layer,
			ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageLayer:
			if encrypt && isUserSelectedLayer(layerNum, layersTotal, lf.Layers) && isUserSelectedPlatform(thisPlatform, lf.Platforms) {
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
		case MediaTypeDockerSchema2LayerGzipEnc, MediaTypeDockerSchema2LayerEnc:
			// this one can be decrypted but also its recpients list changed
			if isUserSelectedLayer(layerNum, layersTotal, lf.Layers) && isUserSelectedPlatform(thisPlatform, lf.Platforms) {
				nl, err := cryptLayer(ctx, cs, child, cc, encrypt)
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
			return ocispec.Descriptor{}, false, errors.Errorf("Bad/unhandled MediaType %s in encryptChildren\n", child.MediaType)
		}
	}

	if modified && len(newLayers) > 0 {
		newManifest := ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: config,
			Layers: newLayers,
		}

		mb, err := json.MarshalIndent(newManifest, "", "   ")
		if err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to marshal image")
		}

		newDesc := ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Size:      int64(len(mb)),
			Digest:    digest.Canonical.FromBytes(mb),
			Platform:  desc.Platform,
		}

		labels := map[string]string{}
		labels["containerd.io/gc.ref.content.0"] = newManifest.Config.Digest.String()
		for i, ch := range newManifest.Layers {
			labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i+1)] = ch.Digest.String()
		}

		ref := fmt.Sprintf("manifest-%s", newDesc.Digest.String())
		if err := content.WriteBlob(ctx, cs, ref, bytes.NewReader(mb), newDesc, content.WithLabels(labels)); err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to write config")
		}
		return newDesc, true, nil
	}

	return desc, modified, nil
}

// cryptManifest encrypts or decrypts the children of a top level manifest
func cryptManifest(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *encryption.CryptoConfig, lf *encryption.LayerFilter, encrypt bool) (ocispec.Descriptor, bool, error) {
	p, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(p, &manifest); err != nil {
		return ocispec.Descriptor{}, false, err
	}
	platform := platforms.DefaultSpec()
	newDesc, modified, err := cryptChildren(ctx, cs, desc, cc, lf, encrypt, &platform)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	return newDesc, modified, nil
}

// cryptManifestList encrypts or decrypts the children of a top level manifest list
func cryptManifestList(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *encryption.CryptoConfig, lf *encryption.LayerFilter, encrypt bool) (ocispec.Descriptor, bool, error) {
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
		newManifest, m, err := cryptChildren(ctx, cs, manifest, cc, lf, encrypt, manifest.Platform)
		if err != nil {
			return ocispec.Descriptor{}, false, err
		}
		if m {
			modified = true
		}
		newManifests = append(newManifests, newManifest)
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

		newDesc := ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageIndex,
			Size:      int64(len(mb)),
			Digest:    digest.Canonical.FromBytes(mb),
		}

		labels := map[string]string{}
		for i, m := range newIndex.Manifests {
			labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i)] = m.Digest.String()
		}

		ref := fmt.Sprintf("index-%s", newDesc.Digest.String())
		if err := content.WriteBlob(ctx, cs, ref, bytes.NewReader(mb), newDesc, content.WithLabels(labels)); err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to write index")
		}
		return newDesc, true, nil
	}

	return desc, false, nil
}

// CryptImage is the dispatcher to encrypt/decrypt an image; it accepts either an OCI descriptor
// representing a manifest list or a single manifest
func CryptImage(ctx context.Context, cs content.Store, desc ocispec.Descriptor, cc *encryption.CryptoConfig, lf *encryption.LayerFilter, encrypt bool) (ocispec.Descriptor, bool, error) {
	switch desc.MediaType {
	case ocispec.MediaTypeImageIndex, MediaTypeDockerSchema2ManifestList:
		return cryptManifestList(ctx, cs, desc, cc, lf, encrypt)
	case ocispec.MediaTypeImageManifest, MediaTypeDockerSchema2Manifest:
		return cryptManifest(ctx, cs, desc, cc, lf, encrypt)
	default:
		return ocispec.Descriptor{}, false, errors.Errorf("CryptImage: Unhandled media type: %s", desc.MediaType)
	}
}

// GetImageLayerInfo gets the image key Ids necessary for decrypting an image
// We determine the KeyIds starting with  the given OCI Decriptor, recursing to lower-level descriptors
// until we get them from the layer descriptors
func GetImageLayerInfo(ctx context.Context, cs content.Store, desc ocispec.Descriptor, lf *encryption.LayerFilter, layerNum int32) ([]encryption.LayerInfo, error) {
	return getImageLayerInfo(ctx, cs, desc, lf, layerNum, platforms.DefaultString())
}

// getImageLayerInfo is the recursive version of GetImageLayerInfo that takes the platform
// as additional parameter
func getImageLayerInfo(ctx context.Context, cs content.Store, desc ocispec.Descriptor, lf *encryption.LayerFilter, layerNum int32, platform string) ([]encryption.LayerInfo, error) {
	var (
		lis []encryption.LayerInfo
		tmp []encryption.LayerInfo
	)

	switch desc.MediaType {
	case MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex,
		MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		children, err := Children(ctx, cs, desc)
		if desc.Platform != nil {
			if !isUserSelectedPlatform(desc.Platform, lf.Platforms) {
				return []encryption.LayerInfo{}, nil
			}
			platform = platforms.Format(*desc.Platform)
		}
		if err != nil {
			if errdefs.IsNotFound(err) {
				return []encryption.LayerInfo{}, nil
			}
			return []encryption.LayerInfo{}, err
		}

		layersTotal := countLayers(children)
		layerNum := int32(-1)

		for _, child := range children {
			if isDescriptorALayer(child) {
				layerNum = layerNum + 1
				if isUserSelectedLayer(layerNum, layersTotal, lf.Layers) {
					tmp, err = getImageLayerInfo(ctx, cs, child, lf, layerNum, platform)
				} else {
					continue
				}
			} else {
				tmp, err = GetImageLayerInfo(ctx, cs, child, lf, -1)
			}
			if err != nil {
				return []encryption.LayerInfo{}, err
			}

			lis = append(lis, tmp...)
		}
	case MediaTypeDockerSchema2Layer, MediaTypeDockerSchema2LayerGzip:
		li := encryption.LayerInfo{
			WrappedKeys: "",
			Digest:      desc.Digest.String(),
			Encryption:  "",
			FileSize:    desc.Size,
			ID:          uint32(layerNum),
			Platform:    platform,
		}
		lis = append(lis, li)
	case MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig:
	case MediaTypeDockerSchema2LayerEnc, MediaTypeDockerSchema2LayerGzipEnc:
		wrappedKeys, err := encryption.GetWrappedKeys(desc)
		if err != nil {
			return []encryption.LayerInfo{}, err
		}
		li := encryption.LayerInfo{
			WrappedKeys: wrappedKeys,
			Digest:      desc.Digest.String(),
			Encryption:  encryption.GetEncryptionScheme(desc),
			FileSize:    desc.Size,
			ID:          uint32(layerNum),
			Platform:    platform,
		}
		lis = append(lis, li)
	default:
		return []encryption.LayerInfo{}, errors.Wrapf(errdefs.ErrInvalidArgument, "GetImageLayerInfo: Unhandled media type %s", desc.MediaType)
	}

	return lis, nil
}

// DecryptLayers decrypts the given array of rootfs.Layer and returns a an array of
// rootfs.Layer with the OCI descriptors adapted to point to the decrypted layers.
// This function will determine the necessary key(s) to decrypt the image and search
// for them using the gpg client
func DecryptLayers(ctx context.Context, cs content.Store, layers []rootfs.Layer, gpgClient encryption.GPGClient, gpgVault encryption.GPGVault) ([]rootfs.Layer, error) {
	var (
		newLayers      []rootfs.Layer
		layerInfos     []encryption.LayerInfo
		err            error
	)

	// in the 1st pass through the layers we gather required keys
	isEncrypted := false
	for id, layer := range layers {
		layerInfo := encryption.LayerInfo{
			ID:       uint32(id),
			Digest:   layer.Blob.Digest.String(),
			Platform: platforms.DefaultString(),
		}
		switch layer.Blob.MediaType {
		case MediaTypeDockerSchema2LayerEnc, MediaTypeDockerSchema2LayerGzipEnc:
			isEncrypted = true
			layerInfo.Encryption = encryption.GetEncryptionScheme(layer.Blob)

			layerInfo.WrappedKeys, err = encryption.GetWrappedKeys(layer.Blob)
			if err != nil {
				return []rootfs.Layer{}, err
			}
		}
		layerInfos = append(layerInfos, layerInfo)
	}

	if !isEncrypted {
		// nothing to do here
		return layers, nil
	}

	// in ctr case we may just want to consult gpg/gpg2 for the key(s)
	dcparameters, err := encryption.GetPrivateKey(layerInfos, gpgClient, gpgVault)
	if err != nil {
		return []rootfs.Layer{}, err
	}
	cc := &encryption.CryptoConfig{
		Dc: &encryption.DecryptConfig{
			Parameters    : dcparameters,
		},
	}

	// in the 2nd pass we decrypt the layers
	for i, layer := range layers {
		if layerInfos[i].Encryption != "" {
			// need to decrypt this layer
			newDesc, err := cryptLayer(ctx, cs, layer.Blob, cc, false)
			if err != nil {
				return []rootfs.Layer{}, err
			}
			fmt.Printf("encrypt:%s -> decrypted:%s\n", layer.Blob.Digest, newDesc.Digest)
			layer.Blob = newDesc
		}
		newLayers = append(newLayers, layer)
	}

	return newLayers, nil
}
