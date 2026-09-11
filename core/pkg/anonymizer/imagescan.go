package anonymizer

import (
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// transformImageScanData applies the supplied Transformer to the image
// references carried alongside a posture scan by --scan-images.
//
// The "img" prefix matches the one container.go uses for a workload's
// spec.containers[].image, so under --hide the image a CVE is reported
// against and the image the workload declares come out string-identical and
// the report still joins. That agreement is the point: leaving this field
// alone leaked more than the reference itself. Per Mapping.GetOrCreate's doc
// comment (mapping.go), a pseudonym's suffix is derived from the raw value
// alone, so a single cleartext occurrence de-anonymizes every img- pseudonym
// sharing that suffix - the cleartext image here was undoing the
// anonymization already applied to the workload side.
//
// Platform stays in cleartext for the same reason transformClusterMetadata
// keeps the cloud provider and worker count: linux/amd64 describes the shape
// of what was scanned rather than naming it. ImageScanData.Target() is
// derived from Image and Platform, so it follows from this.
//
// The remaining fields - Packages, Context, Matches, IgnoredMatches and SBOM -
// hold the Anchore scan graph. They are deliberately not transformed here:
// package identity, pkg.Collection's indexes and the SBOM's relationships are
// all keyed by content-derived artifact IDs that are unexported and would have
// to be recomputed from the very values a rewrite changes, and
// source.ImageMetadata additionally carries RawManifest/RawConfig, the raw OCI
// JSON. A partial scrub of that graph would produce a report the user believes
// is anonymized and is not, which is worse than the leak it replaces.
//
// Nothing is lost by that on this path: the printers that emit the Anchore
// graph are gated so an anonymized run never reaches one. json and yaml emit it
// only when opaSessionObj is nil, the standalone `scan image` path, which
// cmd/scan/image.go rejects for --hide/--encrypt up front
// (shared.ValidateImageScanAnonymization). cyclonedx-json and spdx-json also
// emit it for a posture scan carrying --scan-images, which validateSBOMOutput
// (core/core/scan.go) rejects for the same reason.
func transformImageScanData(imageScanData []cautils.ImageScanData, transformer Transformer) error {
	var err error

	for i := range imageScanData {
		imageScanData[i].Image, err = transformValue(transformer, "img", imageScanData[i].Image)
		if err != nil {
			return err
		}
	}

	return nil
}
