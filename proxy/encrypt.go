package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
)

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, key string, nonce []byte) (string, error) {
	k := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(k[:24])
	if err != nil {
		return "", err
	}
	plainText := []byte(text)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	cipherText := aesgcm.Seal(nil, nonce[:12], plainText, nil)
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, key string, nonce []byte) (string, error) {
	k := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(k[:24])
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	cipherText, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	plainText, err := aesgcm.Open(nil, nonce[:12], []byte(cipherText), nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}
