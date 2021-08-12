package cautils

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// wlid/ sid utils
const (
	SpiffePrefix = "://"
)

// wlid/ sid utils
const (
	PackagePath = "vendor/github.com/armosec/capacketsgo"
)

//AsSHA256 takes anything turns it into string :) https://blog.8bitzen.com/posts/22-08-2019-how-to-hash-a-struct-in-go
func AsSHA256(v interface{}) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", v)))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func SpiffeToSpiffeInfo(spiffe string) (*SpiffeBasicInfo, error) {
	basicInfo := &SpiffeBasicInfo{}

	pos := strings.Index(spiffe, SpiffePrefix)
	if pos < 0 {
		return nil, fmt.Errorf("invalid spiffe %s", spiffe)
	}

	pos += len(SpiffePrefix)
	spiffeNoPrefix := spiffe[pos:]
	splits := strings.Split(spiffeNoPrefix, "/")
	if len(splits) < 3 {
		return nil, fmt.Errorf("invalid spiffe %s", spiffe)
	}

	p0 := strings.Index(splits[0], "-")
	p1 := strings.Index(splits[1], "-")
	p2 := strings.Index(splits[2], "-")
	if p0 == -1 || p1 == -1 || p2 == -1 {
		return nil, fmt.Errorf("invalid spiffe %s", spiffe)
	}
	basicInfo.Level0Type = splits[0][:p0]
	basicInfo.Level0 = splits[0][p0+1:]
	basicInfo.Level1Type = splits[1][:p1]
	basicInfo.Level1 = splits[1][p1+1:]
	basicInfo.Kind = splits[2][:p2]
	basicInfo.Name = splits[2][p2+1:]

	return basicInfo, nil
}

func ImageTagToImageInfo(imageTag string) (*ImageInfo, error) {
	ImageInfo := &ImageInfo{}
	spDelimiter := "/"
	pos := strings.Index(imageTag, spDelimiter)
	if pos < 0 {
		ImageInfo.Registry = ""
		ImageInfo.VersionImage = imageTag
		return ImageInfo, nil
	}

	splits := strings.Split(imageTag, spDelimiter)
	if len(splits) == 0 {

		return nil, fmt.Errorf("Invalid image info %s", imageTag)
	}

	ImageInfo.Registry = splits[0]
	if len(splits) > 1 {
		ImageInfo.VersionImage = splits[len(splits)-1]
	} else {
		ImageInfo.VersionImage = ""
	}

	return ImageInfo, nil
}

func BoolPointer(b bool) *bool { return &b }

func BoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func BoolPointerToString(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

func StringToBool(s string) bool {
	if strings.ToLower(s) == "true" || strings.ToLower(s) == "1" {
		return true
	}
	return false
}

func StringToBoolPointer(s string) *bool {
	if strings.ToLower(s) == "true" || strings.ToLower(s) == "1" {
		return BoolPointer(true)
	}
	if strings.ToLower(s) == "false" || strings.ToLower(s) == "0" {
		return BoolPointer(false)
	}
	return nil
}
