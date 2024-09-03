package license

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/hyperboloide/lk"
)

var getCurrentTime = time.Now

type LicenseInfo struct {
	Identifier          string
	Username            string
	CreatedDate         time.Time
	ExpireDate          time.Time
	Expired             bool
	NumberOfApps        int
	NumberOfAPIRequests int
}

func (l *LicenseInfo) IsExpired() bool {
	return l.ExpireDate.Before(getCurrentTime())
}

type CreateLicenseOpts struct {
	Username            string
	ExpireDate          time.Time
	PrivateKey          string
	NumberOfApps        int
	NumberOfAPIRequests int
}

var validUsernameRegex = regexp.MustCompile("^[a-zA-Z0-9 ]{1,32}$")

var (
	ErrInvalidUsername       = fmt.Errorf("username should be in the form \"[a-zA-Z0-9 ]{1,32}\"")
	ErrInvalidUsernameLength = fmt.Errorf("username should have between 1 and 32 characters")
)

func CreateLicense(opts CreateLicenseOpts) (string, error) {
	privateKey, err := lk.PrivateKeyFromB32String(opts.PrivateKey)
	if err != nil {
		return "", err
	}

	if len(opts.Username) <= 0 || len(opts.Username) > 32 {
		return "", ErrInvalidUsernameLength
	}

	if !validUsernameRegex.MatchString(opts.Username) {
		return "", ErrInvalidUsername
	}

	licenseInfo := LicenseInfo{
		Identifier:          uuid.NewString(),
		Username:            opts.Username,
		CreatedDate:         time.Now().UTC(),
		ExpireDate:          opts.ExpireDate.UTC(),
		Expired:             false,
		NumberOfApps:        -1,
		NumberOfAPIRequests: -1,
	}

	licenseDocBytes, err := json.Marshal(licenseInfo)
	if err != nil {
		return "", err
	}

	license, err := lk.NewLicense(privateKey, licenseDocBytes)
	if err != nil {
		return "", err
	}

	licenseString, err := license.ToB32String()
	if err != nil {
		return "", err
	}

	return licenseString, nil
}

type CheckLicenseOpts struct {
	License   string
	PublicKey string
}

func CheckLicense(opts CheckLicenseOpts) (*LicenseInfo, error) {
	publicKey, err := lk.PublicKeyFromB32String(opts.PublicKey)
	if err != nil {
		return nil, err
	}

	license, err := lk.LicenseFromB32String(opts.License)
	if err != nil {
		return nil, err
	}

	if ok, err := license.Verify(publicKey); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("invalid signature")
	}

	var licenseInfo LicenseInfo
	if err := json.Unmarshal(license.Data, &licenseInfo); err != nil {
		return nil, err
	}

	return &licenseInfo, nil
}
