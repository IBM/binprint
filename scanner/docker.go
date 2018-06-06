// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/image"
	"github.com/docker/docker/pkg/tarsum"

	"github.com/IBM/binprint/record"
)

// NOTES:
//
// Docker is a huge pain because their use of the term "content-addressable
// storage" essentially ignores the transparency aspects that make such systems
// useful. You cannot calculate the digest of a given image without pushing it
// to a registry because it is the registry that calculates it. After pushing,
// the local metadata is updated to include the new repo digest. These repo
// digests can then be used to reference images and pull them down.
//
// When exporting an image via `docker save` the resulting tarball contains
// multiple files with names that _appear_ to be sha256 sums in hex format. Only
// one of them actually is, which is the json config defining an image. The
// layers are stored as tar archives with hash-looking names, but are not
// actually hashed anywhere. It appears that what Docker considers
// content-addressable actually means a hash of a config file that lists a bunch
// of randomly generated IDs :-(

type manifestEntry struct {
	Config   string   `json:"Config"`
	Layers   []string `json:"Layers"`
	RepoTags []string `json:"RepoTags"`
}
type imagesFromTar struct {
	manifestFingerprint     *record.Fingerprint
	Manifest                []manifestEntry
	Images                  map[string]*imageFromTar
	Repositories            map[string]map[string]string
	repositoriesFingerprint *record.Fingerprint
}

type imageFromTar struct {
	fingerprint *record.Fingerprint
	Image       *image.Image
	Config      layerImage
	Inspect     types.ImageInspect
}

type layerImage struct {
	ID     string
	Parent string
	Config struct {
		Image string `json:"Image"`
	}
	Container struct {
		Image string `json:"Image"`
	} `json:"binprint_config"`
}

// IsScannableImage returns true if the name matches a Docker image that exists on the local Docker daemon.
func IsScannableImage(name string) bool {
	ctx := context.Background()
	if cli, err := client.NewEnvClient(); err == nil {
		_, _, err = cli.ImageInspectWithRaw(ctx, name)
		return err == nil
	}
	return false
}

// ScanDockerImages scans docker images, by name, making use of a locally running daemon
func ScanDockerImages(names []string) []*record.DockerImage {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	log.Printf("Scanning docker images: %s", strings.Join(names, ", "))
	stream, err := cli.ImageSave(ctx, names)
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	// fpStream, fpResult := fingerprintPassthrough(stream, 0, nil)
	img := scanDockerImageTarStream(names, stream, nil)
	return img
}

var imageManifestFileName = regexp.MustCompile("[0-9a-fA-F]{64}\\.json")
var layerManifestFileName = regexp.MustCompile("[0-9a-fA-F]{64}/json")

// this is almost identical to scanTarStream, except that it handles the top-level entries as metadata instead of files
// NOTE: this is the docker v1 image archive format, not to be confused with the OCI image layout
func scanDockerImageTarStream(names []string, tarFile io.Reader, fpResult <-chan *record.Fingerprint) []*record.DockerImage {
	flog := log.WithField("file", names).WithField("prefix", "docker")

	imageMeta := new(imagesFromTar)
	imageMeta.Images = make(map[string]*imageFromTar)
	imageMeta.Repositories = make(map[string]map[string]string)
	images := make([]*record.DockerImage, len(names))
	for n, name := range names {
		images[n] = &record.DockerImage{
			Name:   name,
			Layers: make([]*record.DockerLayer, 0, 1),
		}
	}
	layers := make(chan *record.DockerLayer)
	imgLayers := []*record.DockerLayer{}
	done := make(chan error)

	go func() {
		defer close(layers)
		defer close(done)
		// Open and iterate through the files in the image.
		tr := tar.NewReader(tarFile)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break // End of image
			}
			if err == tar.ErrHeader {
				// the 'archive/tar' package goes in to a permanent error state once it hits an error
				// and there's no way to convince it to just skip the bad header, so we just
				// create a new tar.Reader that starts where the previous one left off.
				// We keep doing this until we either get EOF and exit cleanly or some other io error and
				// we exit with a less recoverable error
				tr = tar.NewReader(tarFile)
				continue
			}
			if err != nil {
				log.Println(err)
				done <- err
				return
			}
			if hdr.FileInfo().IsDir() {
				continue
			}

			// flog.Printf("Entry: %s (%d bytes)", hdr.Name, hdr.Size)
			// Layer:
			// <64-hex-digit-id>/VERSION
			// <64-hex-digit-id>/json
			// <64-hex-digit-id>/layer.tar
			// Other:
			// <64-hex-digit-id>.json
			// manifest.json
			// repositories

			// TODO: read/parse the various manifest and metadata files we'll see here...
			if strings.HasSuffix(hdr.Name, "layer.tar") {
				layerName := strings.Split(hdr.Name, "/")[0]
				layerReader, layerFingerprint := fingerprintPassthrough(tr, hdr.Size, nil)
				layers <- scanDockerLayerTarStream(layerName, layerReader, layerFingerprint)
			} else if imageManifestFileName.MatchString(hdr.Name) {
				file, fpCh := fingerprintPassthrough(tr, hdr.Size, nil)
				manifestJSON, err := ioutil.ReadAll(file)
				if err != nil {
					flog.WithError(err).Printf("Could not read image manifest %s", hdr.Name)
					continue
				}
				imageManifest, err := image.NewFromJSON(manifestJSON)
				if err != nil {
					flog.WithError(err).Printf("Could not parse image manifest %s", hdr.Name)
					continue
				}
				// flog.Printf("Image %s: %#v", hdr.Name, imageManifest)
				// fp := <-fpCh
				if _, ok := imageMeta.Images[hdr.Name]; !ok {
					imageMeta.Images[hdr.Name] = &imageFromTar{}
				}
				imageMeta.Images[hdr.Name].fingerprint = <-fpCh
				imageMeta.Images[hdr.Name].Image = imageManifest
				// flog.Printf("Image (%s) %#v", fp.SHA256, imageManifest.V1Image)
			} else if layerManifestFileName.MatchString(hdr.Name) {
				file, fpCh := fingerprintPassthrough(tr, hdr.Size, nil)
				layer := &layerImage{}
				if err := json.NewDecoder(file).Decode(&layer); err != nil {
					flog.WithError(err).Print("Failed to read layer json")
				}
				// layer := &layer.Layer{}
				// if err := json.Unmarshal(manifestJSON, layer); err != nil {
				// 	flog.WithError(err).Printf("Could not parse layer manifest %s", hdr.Name)
				// 	continue
				// }
				// fp := <-fpCh
				// layerName := strings.Split(hdr.Name, "/")[0]
				// flog.Printf("Layer %s (%s) %+v", layerName, fp.SHA256, layer)
				<-fpCh
			} else if hdr.Name == "manifest.json" {
				file, fpCh := fingerprintPassthrough(tr, hdr.Size, nil)
				if err := json.NewDecoder(file).Decode(&imageMeta.Manifest); err != nil {
					flog.WithError(err).Print("Failed to read manifest.json")
				}
				imageMeta.manifestFingerprint = <-fpCh

				ctx := context.Background()
				cli, err := client.NewEnvClient()
				if err != nil {
					panic(err)
				}
				for _, m := range imageMeta.Manifest {
					if _, ok := imageMeta.Images[m.Config]; !ok {
						imageMeta.Images[m.Config] = &imageFromTar{}
					}
					imageMeta.Images[m.Config].Inspect, _, err = cli.ImageInspectWithRaw(ctx, m.RepoTags[0])
					if err != nil {
						flog.WithError(err).Printf("Could not inspect image %s (%s)", m.Config, m.RepoTags[0])
					}
				}
			} else if hdr.Name == "repositories" {
				file, fpCh := fingerprintPassthrough(tr, hdr.Size, nil)
				if err := json.NewDecoder(file).Decode(&imageMeta.Repositories); err != nil {
					flog.WithError(err).Print("Failed to unmarshal repositories")
				}
				imageMeta.repositoriesFingerprint = <-fpCh
			} else {
				payload, err := ioutil.ReadAll(tr)
				flog.WithError(err).Printf("%s: %s", hdr.Name, payload)
			}
		}
		done <- nil
	}()

readLoop:
	for {
		select {
		case err := <-done:
			if err != nil {
				flog.WithError(err).Println("Error scanning")
				for range layers {
				}
				return nil
			}
			break readLoop
		case layer := <-layers:
			if layer != nil {
				imgLayers = append(imgLayers, layer)
			}
		}
	}

	if len(fpResult) == 0 {
		if err := consumeRemainder(tarFile); err != nil {
			flog.WithError(err).Print("Error consuming archive trailer")
		}
	}

	// this fingerprint probably isn't actually useful :-(
	// img.Fingerprint = <-fpResult

	// list the layers in the official record in the same order they are in the
	// image manifest, which may be different than the order they were read
	for ii, m := range imageMeta.Manifest {
		images[ii].ImageID = m.Config
		images[ii].RepoDigests = imageMeta.Images[m.Config].Inspect.RepoDigests
		images[ii].Layers = make([]*record.DockerLayer, len(m.Layers))
		for i, lid := range m.Layers {
			id := strings.Split(lid, "/")[0]
			for _, l := range imgLayers {
				if l.Name == id {
					images[ii].Layers[i] = l
				}
			}
		}
	}

	// flog.Printf("Image: %v", imageMeta)

	return images
}

func scanDockerLayerTarStream(fileName string, layerReader io.Reader, fpResult <-chan *record.Fingerprint) *record.DockerLayer {
	flog := log.WithField("file", fileName).WithField("prefix", "docker")

	// tarsum implements a pass through pattern where the TarSum interface includes io.Reader
	// so that it calculates the tarsum as you read from it
	tarSum, err := tarsum.NewTarSum(layerReader, false, tarsum.Version1)
	if err != nil {
		flog.WithError(err).Printf("Could not create tarsum pass through")
	}
	// tarFile := tarSum.(io.Reader)
	tarFile := layerReader

	layer := &record.DockerLayer{
		Name:  fileName,
		Files: make([]*record.File, 0, 1),
	}
	layer.Name = fileName
	entries := make(chan *record.File)
	done := make(chan error)

	go func() {
		defer close(entries)
		defer close(done)
		// Open and iterate through the files in the layer.
		tr := tar.NewReader(tarFile)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break // End of image
			}
			if err == tar.ErrHeader {
				// the 'archive/tar' package goes in to a permanent error state once it hits an error
				// and there's no way to convince it to just skip the bad header, so we just
				// create a new tar.Reader that starts where the previous one left off.
				// We keep doing this until we either get EOF and exit cleanly or some other io error and
				// we exit with a less recoverable error
				tr = tar.NewReader(tarFile)
				continue
			}
			if err != nil {
				log.Println(err)
				done <- err
				return
			}
			if hdr.FileInfo().IsDir() {
				continue
			}

			// TODO: decide if/how we want to handle whiteout entries
			entries <- fingerprintArchiveEntry(hdr.Name, hdr.Size, tr, 0, 10)
		}
		done <- nil
	}()

readLoop:
	for {
		select {
		case err := <-done:
			if err != nil {
				flog.WithError(err).Println("Error scanning")
				for range entries {
				}
				return nil
			}
			break readLoop
		case entry := <-entries:
			if layer != nil {
				layer.Files = append(layer.Files, entry)
			}
		}
	}

	if len(fpResult) == 0 {
		if err := consumeRemainder(tarFile); err != nil {
			flog.WithError(err).Print("Error consuming archive trailer")
		}
	}

	layer.Fingerprint = <-fpResult
	layer.TarSum = tarSum.Sum(nil)
	return layer
}

// DumpDockerImage lists the files in an image, by layer
func DumpDockerImage(i *record.DockerImage) {
	fmt.Printf("Image: %s (%s, %s)\n", i.Name, i.ImageID, i.RepoDigests)
	fmt.Printf("  layers:\n")
	for _, layer := range i.Layers {
		fmt.Printf("    %s: (%d bytes, %s)\n", layer.Name, layer.Fingerprint.Size, layer.TarSum)
		for _, file := range layer.Files {
			fmt.Printf("     - %s (%d bytes, %s)\n", file.Path, file.Fingerprint.Size, file.Fingerprint.GitSHA)
		}
	}
}
