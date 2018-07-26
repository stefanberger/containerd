package images

import (
	"fmt"
	"io/ioutil"
	"os/exec"

	"github.com/containerd/containerd/errdefs"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

// GPGVersion enum representing the versino of GPG client to use.
type GPGVersion int

const (
	// GPGv2 signifies gpgv2+
	GPGv2 GPGVersion = iota
	// GPGv2 signifies gpgv1+
	GPGv1
	// GPGVersionUndetermined signifies gpg client version undetermined
	GPGVersionUndetermined
)

// GPG
type GPGClient interface {
	// ReadGPGPubRingFile gets the byte sequence of the gpg public keyring
	ReadGPGPubRingFile() ([]byte, error)
	// GetGPGPrivateKey gets the private key bytes of a keyid given a passphrase
	GetGPGPrivateKey(keyid uint64, passphrase string) ([]byte, error)
	// GetSecretKeyDetails gets the details of a secret key
	GetSecretKeyDetails(keyid uint64) ([]byte, bool, error)
}

// TODO: add comment and make private
type gpgClient struct {
	gpgHomeDir string
}
type gpgv2Client struct {
	gpgClient
}

type gpgv1Client struct {
	gpgClient
}

// GuessGPGVersion guesses the version of gpg. Defaults to gpg2 if exists, if
// not defaults to regular gpg.
func GuessGPGVersion() GPGVersion {
	if err := exec.Command("gpg2", "--version").Run(); err == nil {
		return GPGv2
	} else if err := exec.Command("gpg", "--version").Run(); err == nil {
		return GPGv1
	} else {
		return GPGVersionUndetermined
	}
}

func NewGPGClient(version *GPGVersion, homedir string) (GPGClient, error) {
	var gpgVersion GPGVersion
	if version != nil {
		gpgVersion = *version
	} else {
		gpgVersion = GuessGPGVersion()
	}

	switch gpgVersion {
	case GPGv1:
		return &gpgv1Client{
			gpgClient: gpgClient{gpgHomeDir: homedir},
		}, nil
	case GPGv2:
		return &gpgv2Client{
			gpgClient: gpgClient{gpgHomeDir: homedir},
		}, nil
	case GPGVersionUndetermined:
		return nil, fmt.Errorf("Unable to determine GPG version")
	default:
		return nil, fmt.Errorf("Unhandled case: NewGPGClient")
	}
}

// GetGPGPrivateKey gets the bytes of a specified keyid, supplying a passphrase
func (_ *gpgv2Client) GetGPGPrivateKey(keyid uint64, passphrase string) ([]byte, error) {
	args := append([]string{"--pinentry-mode", "loopback", "--batch", "--passphrase", passphrase, "--export-secret-key"}, fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	keydata, err2 := ioutil.ReadAll(stdout)
	message, _ := ioutil.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("Error from gpg2: %s\n", message)
	}

	return keydata, err2
}

// ReadGPGPubRingFile reads the GPG public key ring file
func (_ *gpgv2Client) ReadGPGPubRingFile() ([]byte, error) {
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	pubring := fmt.Sprintf("%s/.gnupg/pubring.gpg", home)
	gpgPubRingFile, err := ioutil.ReadFile(pubring)
	if err != nil {
		return nil, fmt.Errorf("Could not read Public keyring file %s: %v", pubring, err)
	}
	return gpgPubRingFile, nil
}

// GetSecretKeyDetails retrives the secret key details of key with keyid.
// returns a byte array of the details and a bool if the key exists
func (gc *gpgv2Client) GetSecretKeyDetails(keyid uint64) ([]byte, bool, error) {
	var args []string

	if gc.gpgHomeDir != "" {
		args = append([]string{"--homedir", gc.gpgHomeDir})
	}
	args = append(args, "-K", fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, err
	}

	keydata, err2 := ioutil.ReadAll(stdout)
	message, _ := ioutil.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, false, fmt.Errorf("Error from gpg2: %s\n", message)
	}

	return keydata, err2 == nil, err2
}

// GetGPGPrivateKey gets the bytes of a specified keyid, supplying a passphrase
func (_ *gpgv1Client) GetGPGPrivateKey(keyid uint64, passphrase string) ([]byte, error) {
	args := append([]string{"--pinentry-mode", "loopback", "--batch", "--passphrase", passphrase, "--export-secret-key"}, fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	keydata, err2 := ioutil.ReadAll(stdout)
	message, _ := ioutil.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, errors.Wrapf(errdefs.ErrUnknown, "Error from gpg2: %s\n", message)
	}

	return keydata, err2
}

// ReadGPGPubRingFile reads the GPG public key ring file
func (_ *gpgv1Client) ReadGPGPubRingFile() ([]byte, error) {
	var pubringfn string
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
		pubringfn = fmt.Sprintf("%s/.gnupg/pubring.gpg", home)
	}

	gpgPubRingFile, err := ioutil.ReadFile(pubringfn)
	if err != nil {
		return nil, errors.Wrapf(errdefs.ErrInvalidArgument, "Could not read Public keyring file %s: %v", pubringfn, err)
	}
	return gpgPubRingFile, nil
}

// GetSecretKeyDetails retrives the secret key details of key with keyid.
// returns a byte array of the details and a bool if the key exists
func (gc *gpgv1Client) GetSecretKeyDetails(keyid uint64) ([]byte, bool, error) {
	var args []string

	if gc.gpgHomeDir != "" {
		args = append([]string{"--homedir", gc.gpgHomeDir})
	}
	args = append(args, "-K", fmt.Sprintf("0x%x", keyid))

	cmd := exec.Command("gpg2", args...)

	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, err
	}

	keydata, err2 := ioutil.ReadAll(stdout)
	message, _ := ioutil.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, false, fmt.Errorf("Error from gpg2: %s\n", message)
	}

	return keydata, err2 == nil, err2
}
