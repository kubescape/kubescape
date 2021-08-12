package ocimage

import "github.com/docker/docker/api/types/container"

// FileMetadata file metatdata
type FileMetadata struct {
	IsSymbolicLink bool   `json:"isSymbolicLink"`
	Layer          string `json:"layer"`
	Link           string `json:"link"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	Permissions    string `json:"permissions"`
}

// ImageMetadata image metatdata
type ImageMetadata struct {
	Tag           string               `json:"tag"`
	Name          string               `json:"name"`
	Architecture  string               `json:"architecture"`
	SchemaVersion int                  `json:"naschemaVersionme"`
	Info          ImageMetaInfo        `json:"info"`
	Signatures    []ImageMetaSignature `json:"signatures"`
}

// ImageMetaInfo -
type ImageMetaInfo struct {
	ID              string            `json:"id,omitempty"`
	Os              string            `json:"os,omitempty"`
	Parent          string            `json:"parent,omitempty"`
	Created         string            `json:"created,omitempty"`
	Container       string            `json:"container,omitempty"`
	Architecture    string            `json:"architecture,omitempty"`
	Config          *container.Config `json:"config,omitempty"`
	ContainerConfig *container.Config `json:"container_config,omitempty"`
}

// // ContainerInfo -
// type ContainerInfo struct {
// 	Tty          bool                   `json:"Tty,omitempty"`
// 	ArgsEscaped  bool                   `json:"ArgsEscaped,omitempty"`
// 	AttachStderr bool                   `json:"AttachStderr,omitempty"`
// 	AttachStdin  bool                   `json:"AttachStdin,omitempty"`
// 	AttachStdout bool                   `json:"AttachStdout,omitempty"`
// 	OpenStdin    bool                   `json:"OpenStdin,omitempty"`
// 	StdinOnce    bool                   `json:"StdinOnce,omitempty"`
// 	User         string                 `json:"User,omitempty"`
// 	Image        string                 `json:"Image"`
// 	Hostname     string                 `json:"Hostname,omitempty"`
// 	Domainname   string                 `json:"Domainname,omitempty"`
// 	WorkingDir   string                 `json:"WorkingDir,omitempty"`
// 	Cmd          []string               `json:"Cmd"`
// 	Env          []string               `json:"Env,omitempty"`
// 	Entrypoint   []string               `json:"Entrypoint"`
// 	Volumes      interface{}            `json:"Volumes,omitempty"`
// 	OnBuild      []interface{}          `json:"OnBuild,omitempty"`
// 	Labels       map[string]string      `json:"Labels,omitempty"`
// 	ExposedPorts map[string]interface{} `json:"ExposedPorts,omitempty"`
// }

// ImageMetaSignature -
type ImageMetaSignature struct {
	Protected string          `json:"protected,omitempty"`
	Signature string          `json:"signature,omitempty"`
	Header    SignatureHeader `json:"header,omitempty"`
}

// SignatureHeader -
type SignatureHeader struct {
	Alg string    `json:"alg,omitempty"`
	Jwk HeaderJwk `json:"jwk,omitempty"`
}

// HeaderJwk -
type HeaderJwk struct {
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type OciImageManifestConfig struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
}

type OciImageManifestRequestOptions struct {
	AllowRedirects bool              `json:"allow_redirects"`
	Stream         bool              `json:"stream"`
	Verify         bool              `json:"verify"`
	Headers        map[string]string `json:"headers"`
}

type OciImageManifestLayer struct {
	Digest         string                         `json:"digest"`
	DownloadPath   string                         `json:"dlPath"`
	MediaType      string                         `json:"mediaType"`
	Size           int                            `json:"size"`
	RequestOptions OciImageManifestRequestOptions `json:"request_options"`
}

type OciImageManifest struct {
	Config OciImageManifestConfig  `json:"config"`
	Layers []OciImageManifestLayer `json:"layers"`
}

//{"isSymbolicLink":false,"layer":"sha256:86b54f4b6a4ebee33338eb7c182a9a3d51a69cce1eb9af95a992f4da8eabe3be","link":"","name":"var/lib/dpkg/info/libdbus-1-3.list","path":"var/lib/dpkg/info/libdbus-1-3.list","permissions":"0o100644"},
type OciImageFsEntry struct {
	IsSymbolicLink bool   `json:"isSymbolicLink"`
	Layer          string `json:"layer"`
	Link           string `json:"link"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	Permissions    string `json:"permissions"`
}
