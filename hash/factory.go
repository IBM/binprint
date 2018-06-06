package hash

import (
	"fmt"
)

// NewAsyncHash returns an AsyncHash that implements the requested hash. Only
// some algorithms require knowing the size of the input first (git sha1).
func NewAsyncHash(algorithm string, size int64) (AsyncHash, error) {
	switch algorithm {
	case "md5":
		return NewMD5Hasher(), nil
	case "sha1":
		return NewSHA1Hasher(), nil
	case "sha256":
		return NewSHA256Hasher(), nil
	case "sha384":
		return NewSHA384Hasher(), nil
	case "sha512":
		return NewSHA512Hasher(), nil
	case "git", "gitsha":
		return NewGitShaHasher(size), nil
	case "hwy64":
		return NewHighway64Hasher(), nil
	case "hwy128":
		return NewHighway128Hasher(), nil
	case "hwy256":
		return NewHighway256Hasher(), nil
	default:
		return nil, fmt.Errorf("unsupported hash %s", algorithm)
	}
}
