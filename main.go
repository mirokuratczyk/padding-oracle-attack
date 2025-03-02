package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Encrypt plaintext with aesKey.
func encrypt(aesKey []byte, plaintext []byte) ([]byte, error) {

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("NewCipher failed: %w", err)
	}

	plaintext, _ = pkcs7Pad(plaintext, block.BlockSize())

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("ReadFull failed: %w", err)
	}

	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// Decrypt ciphertext with aesKey.
func decrypt(aesKey []byte, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("NewCipher failed: %w", err)
	}

	iv := ciphertext[:aes.BlockSize]
	paddedPlaintext := make([]byte, len(ciphertext)-len(iv))

	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(paddedPlaintext, ciphertext[aes.BlockSize:])

	fmt.Printf("paddedPlaintext=%s\n", fmtBlocks(paddedPlaintext))

	plaintext, err := pkcs7Unpad(paddedPlaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("pkcs7Unpad failed: %w", err)
	}

	return plaintext, nil
}

func fmtBlocks(blocks []byte) string {
	s := ""

	i := 0
	for {
		if len(blocks) < (i+1)*aes.BlockSize {
			break
		}
		encoded := hex.EncodeToString(blocks[i*aes.BlockSize : (i+1)*aes.BlockSize])
		if s == "" {
			s = encoded
		} else {
			s = fmt.Sprintf("%s %s", s, encoded)
		}
		i++
	}

	return s
}

// Ciphertext is ( IV | ciphertext ) in this example, but the IV is only needed
// to decrypt the first block.
//
// oracle returns true if decrypted plaintext has valid PKCS#7 padding;
// otherwise returns false.
func paddingOracleAttack(oracle func([]byte) (bool, error), ciphertext []byte) ([]byte, error) {

	// Remember len(ciphertext) will be multiple of aes.BlockSize due to PKCS7
	// padding.

	var paddedPlaintext []byte

	for blockIndex := 0; blockIndex < len(ciphertext)/16-1; blockIndex++ {

		encryptedBlock := ciphertext[16*blockIndex : 16*(blockIndex+2)]

		intermediates := make([]byte, aes.BlockSize)
		decryptedBlock := make([]byte, aes.BlockSize)

		// NOTE: byteIndex is the index of the byte in C1' we will manipulate
		// until the padding of P2' is correct.
		for byteIndex := aes.BlockSize - 1; byteIndex >= 0; byteIndex-- {

			// 0x01, 0x02, 0x03, ..., 0x10 (0-16).
			padding := byte(aes.BlockSize - byteIndex)

			// Manipulate the proceeding block
			tamperEndIndex := aes.BlockSize - 1
			tamperCiphertext := make([]byte, len(encryptedBlock))
			copy(tamperCiphertext[tamperEndIndex:], encryptedBlock[tamperEndIndex:])

			// Fill C1' with random bytes
			if _, err := io.ReadFull(rand.Reader, tamperCiphertext[0:tamperEndIndex]); err != nil {
				return nil, fmt.Errorf("ReadFull failed: %w", err)
			}

			var probe byte = 0x00

			for {
				tamperCiphertext[byteIndex] = probe

				for i := byteIndex + 1; i < aes.BlockSize; i++ {
					tamperCiphertext[i] = padding ^ intermediates[i]
				}

				fmt.Printf("C1'=%s\n", fmtBlocks(tamperCiphertext))

				paddingOk, err := oracle(tamperCiphertext)
				if err != nil {
					return nil, fmt.Errorf("oracle failed: %w", err)
				}

				if !paddingOk {
					if probe == 0xff {
						return nil, errors.New("maxed out probe")
					}
					probe++
					continue
				}

				// Final test: ensure that altering the target byte resulted in
				// the correct padding by altering all proceeding bytes.

				finalTestCiphertext := make([]byte, len(tamperCiphertext))
				copy(finalTestCiphertext, tamperCiphertext)

				for i := 0; i < byteIndex; i++ {
					finalTestCiphertext[i] = finalTestCiphertext[i] ^ 0x11
				}

				fmt.Printf("(final test) C1'=%s\n", fmtBlocks(finalTestCiphertext))

				paddingOk, err = oracle(tamperCiphertext)
				if err != nil {
					return nil, fmt.Errorf("oracle failed: %w", err)
				}

				if !paddingOk {
					if probe == 0xff {
						return nil, errors.New("maxed out probe")
					}
					probe++
					continue
				}
				break
			}

			intermediate := probe ^ padding
			answer := intermediate ^ encryptedBlock[byteIndex]
			decryptedBlock[byteIndex] = answer
			intermediates[byteIndex] = intermediate

			fmt.Printf("C1'[%d]=%x\n", byteIndex, probe)
			fmt.Printf("I[%d]=%x\n", byteIndex, intermediate)
			fmt.Printf("P2[%d]=%x\n", byteIndex, answer)

			padding++
		}

		fmt.Printf("block[%d]=%x\n", blockIndex+1, decryptedBlock)
		fmt.Printf("decrypt(block[%d])=%s\n", blockIndex+1, string(decryptedBlock))

		paddedPlaintext = append(paddedPlaintext, decryptedBlock...)
	}

	plaintext, err := pkcs7Unpad(paddedPlaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("pkcs7Unpad failed: %w", err)
	}

	return plaintext, nil
}

func main() {

	// generate a random key

	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Printf("ReadFull failed: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Generated key: %s\n", hex.EncodeToString(key))

	originalPlaintext := []byte("my secret plaintext 12345")

	ciphertext, err := encrypt(key, []byte(originalPlaintext))
	if err != nil {
		fmt.Printf("encrypt failed: %v\n", err)
		os.Exit(1)
	}

	// Padding oracle. Returns true if decrypted plaintext has valid
	// pkcs7 padding; otherwise returns false.
	oracle := func(ciphertext []byte) (bool, error) {
		_, err := decrypt(key, ciphertext)
		if err != nil {
			if errors.Is(err, ErrInvalidPKCS7Padding) {
				return false, nil
			}
			return false, fmt.Errorf("decrypt failed: %w", err)
		}
		return true, nil
	}

	plaintext, err := paddingOracleAttack(oracle, ciphertext)
	if err != nil {
		fmt.Printf("paddingOracleAttack failed: %v", err)
		os.Exit(1)
	}

	fmt.Printf("padding oracle attack decrypted: \"%s\"\n", string(plaintext))
	if bytes.Equal(originalPlaintext, plaintext) {
		fmt.Println("padding oracle attack succeeded: decrypted plaintext matches original plaintext")
	} else {
		fmt.Println("padding oracle attack failed: decrypted plaintext does not match original plaintext")
		os.Exit(1)
	}

	// plaintext, err = decrypt(key, ciphertext)
	// if err != nil {
	// 	fmt.Printf("decrypt failed: %v\n", err)
	// 	os.Exit(1)
	// }
	// if !bytes.Equal(originalPlaintext, plaintext) {
	// 	fmt.Println("decrypt failed: decrypted plaintext does not match original plaintext")
	// 	os.Exit(1)
	// }
	// fmt.Printf("decrypted: %s\n", string(plaintext))
}
