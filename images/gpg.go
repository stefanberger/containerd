package images

import (
	"fmt"
	"io/ioutil"
	"os/exec"

	"github.com/mitchellh/go-homedir"
)

// GPGVersion enum representing the versino of GPG client to use.
type GPGVersion int

const (
	GPGv2 GPGVersion = iota
	GPGv1
	GPGVersionUndetermined
)

type GPGClient interface {
	ReadGPGPubRingFile() ([]byte, error)
	GetGPGPrivateKey(keyid uint64, password string) ([]byte, error)
}

// GuessGPGVersion guesses the version of gpg. Defaults to gpg2 if exists, if
// not defaults to regular gpg.
func GuessGPGVersion() (GPGVersion, error) {
	return GPGVersionUndetermined, nil
}

// GetGPGPrivateKey gets the bytes of a specified keyid, supplying a passphrase
func GetGPGPrivateKey(keyid uint64, password string) ([]byte, error) {
	args := append([]string{"--pinentry-mode", "loopback", "--batch", "--passphrase", password, "--  export-secret-key"}, fmt.Sprintf("0x%x", keyid))

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
func ReadGPGPubRingFile() ([]byte, error) {
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
