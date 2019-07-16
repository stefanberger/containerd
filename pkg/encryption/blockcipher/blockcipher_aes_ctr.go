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

package blockcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"github.com/pkg/errors"
)

// AESCTRLayerBlockCipher implements the AES CTR stream cipher
type AESCTRLayerBlockCipher struct {
	keylen    int // in bytes
	reader    io.Reader
	encrypt   bool
	stream    cipher.Stream
	err       error
	eof       bool
	hmac      hash.Hash
	expDigest string
	hmacBuf   *[]byte
	expHmac   []byte
}

type aesctrcryptor struct {
	bc           *AESCTRLayerBlockCipher
	outputReader io.Reader
}

// NewAESCTRLayerBlockCipher returns a new AES SIV block cipher of 256 or 512 bits
func NewAESCTRLayerBlockCipher(bits int) (LayerBlockCipher, error) {
	if bits != 256 {
		return nil, errors.New("AES CTR bit count not supported")
	}
	return &AESCTRLayerBlockCipher{keylen: bits / 8}, nil
}

func (r *aesctrcryptor) Read(p []byte) (int, error) {
	if r.bc.err != nil {
		return 0, r.bc.err
	}

	if r.bc.eof {
		return 0, io.EOF
	}

	n, err := r.bc.reader.Read(p)
	if err != nil {
		if err == io.EOF {
			r.bc.eof = true
		} else {
			return 0, err
		}
	}

	if !r.bc.encrypt {
		r.bc.hmac.Write(p[:n])
		if r.bc.eof {
			if !hmac.Equal(r.bc.hmac.Sum(nil), r.bc.expHmac) {
				return 0, fmt.Errorf("could not properly decrypt byte stream; exp hmac: '%x', actual hmac: '%s'", r.bc.expHmac, r.bc.hmac.Sum(nil))
			}
		}
	}

	r.bc.stream.XORKeyStream(p[:n], p[:n])

	if r.bc.encrypt {
		fmt.Printf("encrypting %d bytes! eof: %t\n", n, r.bc.eof)
		r.bc.hmac.Write(p[:n])
		if r.bc.eof {
			*r.bc.hmacBuf = r.bc.hmac.Sum(nil)
			fmt.Printf("Created HMAC: %x (%x)\n", *r.bc.hmacBuf, r.bc.hmac.Sum(nil))
		}
	}

	return n, nil
}

// init initializes an instance
func (bc *AESCTRLayerBlockCipher) init(encrypt bool, reader io.Reader, opts LayerBlockCipherOptions, hmacBuf *[]byte, expHmac []byte) (LayerBlockCipherOptions, error) {
	var (
		err error
	)

	bc.encrypt = encrypt
	bc.reader = reader
	bc.expDigest = opts.Digest.String()

	key := opts.SymmetricKey
	if len(key) != bc.keylen {
		return LayerBlockCipherOptions{}, fmt.Errorf("invalid key length of %d bytes; need %d bytes", len(key), bc.keylen)
	}

	nonce := opts.CipherOptions["nonce"]
	if len(nonce) == 0 {
		nonce = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return LayerBlockCipherOptions{}, errors.Wrap(err, "unable to generate random nonce")
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return LayerBlockCipherOptions{}, errors.Wrap(err, "aes.NewCipher failed")
	}

	bc.stream = cipher.NewCTR(block, nonce)
	bc.hmac = hmac.New(sha256.New, key)
	bc.hmacBuf = hmacBuf
	bc.expHmac = expHmac

	lbco := LayerBlockCipherOptions{
		SymmetricKey: key,
		CipherOptions: map[string][]byte{
			"nonce": nonce,
		},
	}

	return lbco, nil
}

// GenerateKey creates a synmmetric key
func (bc *AESCTRLayerBlockCipher) GenerateKey() ([]byte, error) {
	key := make([]byte, bc.keylen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt takes in layer data and returns the ciphertext and relevant LayerBlockCipherOptions
func (bc *AESCTRLayerBlockCipher) Encrypt(plainDataReader io.Reader, opt LayerBlockCipherOptions, hmac *[]byte) (io.Reader, LayerBlockCipherOptions, error) {
	lbco, err := bc.init(true, plainDataReader, opt, hmac, nil)
	if err != nil {
		return nil, LayerBlockCipherOptions{}, err
	}

	return &aesctrcryptor{bc, nil}, lbco, nil
}

// Decrypt takes in layer ciphertext data and returns the plaintext and relevant LayerBlockCipherOptions
func (bc *AESCTRLayerBlockCipher) Decrypt(encDataReader io.Reader, opt LayerBlockCipherOptions, expHmac []byte) (io.Reader, LayerBlockCipherOptions, error) {
	lbco, err := bc.init(false, encDataReader, opt, nil, expHmac)
	if err != nil {
		return nil, LayerBlockCipherOptions{}, err
	}

	return &aesctrcryptor{bc, nil}, lbco, nil
}
