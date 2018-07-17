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

	EncryptImage(ctx context.Context, name string, ec *EncryptConfig) (Image, error)
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
		fmt.Printf("images/image: Size()")
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

			if platform != nil {
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

// encryptLayer encryts a single layer and writes the encrypted layer back into storage
func encryptLayer(ctx context.Context, provider content.Store, desc ocispec.Descriptor, ec *EncryptConfig) (ocispec.Descriptor, error) {
	plain, err := content.ReadBlob(ctx, provider, desc);
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	//fmt.Printf("   ... read %d bytes of layer %s data\n", len(p), desc.Digest)
	// now we should encrypt

	p, err := Encrypt(ec, plain)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	size := int64(len(p))
	d := digest.FromBytes(p)

	encDesc := ocispec.Descriptor{
		Digest:   d,
		Size:     size,
		Platform: desc.Platform,
	}
	encDesc.Annotations = make(map[string]string)
	encDesc.Annotations["org.opencontainers.image.pgp.keys"] = "foo-bar"

	switch (desc.MediaType) {
	case MediaTypeDockerSchema2LayerGzip:
		encDesc.MediaType = MediaTypeDockerSchema2LayerGzipPGP
	case MediaTypeDockerSchema2Layer:
		encDesc.MediaType = MediaTypeDockerSchema2LayerPGP
	default:
		return ocispec.Descriptor{}, fmt.Errorf("Unsupporter layer MediaType: %s\n", desc.MediaType)
	}

	fmt.Printf("   ... writing layer %s in encrypted form as %s\n", desc.Digest, d)
	ref := fmt.Sprintf("layer-%s", encDesc.Digest.String())
	content.WriteBlob(ctx, provider, ref, bytes.NewReader(p), encDesc);

	return encDesc, nil
}

// Encrypt all the Children of a given descriptor
func encryptChildren(ctx context.Context, cs content.Store, desc ocispec.Descriptor, ec *EncryptConfig) (ocispec.Descriptor, bool, error) {
	//fmt.Printf("metadata/image.go EncryptChildren(): Getting Children of %s [%s]\n", desc.MediaType, desc.Digest)
	children, err := Children(ctx, cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	//fmt.Printf("metadata/image.go EncryptChildren(): got %d children\n", len(children))
	var newLayers []ocispec.Descriptor
	var config ocispec.Descriptor
	modified := false;

	for _, child := range children {
		// we only encrypt child layers and have to update their parents if encyrption happened
		//fmt.Printf("   child : %s\n", child.MediaType)
		switch child.MediaType {
		case MediaTypeDockerSchema2Config:
			config = child
		case MediaTypeDockerSchema2LayerGzip,MediaTypeDockerSchema2Layer:
			//fmt.Printf("   ... a layer to encrypt\n")
			nl, err := encryptLayer(ctx, cs, child, ec)
			if err != nil {
				return ocispec.Descriptor{}, false, err
			}
			modified = true
			newLayers = append(newLayers, nl)
		default:
			return ocispec.Descriptor{}, false, fmt.Errorf("Bad/unhandled MediaType %s in encryptChildren\n", child.MediaType)
		}
	}

	if len(newLayers) > 0 {
		nM := ocispec.Manifest {
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config : config,
			Layers: newLayers,
		}

		mb, err := json.MarshalIndent(nM, "", "   ")
		if err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to marshal image")
		}

		nDesc := ocispec.Descriptor{
			MediaType: MediaTypeDockerSchema2Manifest,//ocispec.MediaTypeImageManifest,//MediaTypeDockerSchema2Manifest,
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

	return ocispec.Descriptor{}, modified, nil
}

// EncryptChildren encrypts the children of a top level manifest list
func EncryptChildren(ctx context.Context, cs content.Store, desc ocispec.Descriptor, ec *EncryptConfig) (ocispec.Descriptor, bool, error) {
	if desc.MediaType != MediaTypeDockerSchema2ManifestList {
		return ocispec.Descriptor{}, false, fmt.Errorf("Wrong media type %s passed. Need %s.\n", desc.MediaType, MediaTypeDockerSchema2ManifestList)
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
		newManifest, m, err := encryptChildren(ctx, cs, manifest, ec)
		if err != nil {
			return ocispec.Descriptor{}, false, err
		}
		newManifests = append(newManifests, newManifest)
		if m {
			modified = true
		}
	}

	if (modified) {
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

		ref := fmt.Sprintf("index-%s", nDesc.Digest.String())
		if err := content.WriteBlob(ctx, cs, ref, bytes.NewReader(mb), nDesc); err != nil {
			return ocispec.Descriptor{}, false, errors.Wrap(err, "failed to write index")
		}
		return nDesc, true, nil
	}

	return desc, false, nil
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
