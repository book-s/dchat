package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
)

// 加密文件
func encryptFile(filename string, key []byte) ([]byte, error) {
	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// 使用公钥加密AES密钥
func encryptAESKey(publicKey *rsa.PublicKey, key []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, key)
}

// 上传加密文件和加密的AES密钥
func uploadFileAndKey(url string, encryptedFile, encryptedKey []byte) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	fileWriter, err := writer.CreateFormFile("encryptedFile", "file.enc")
	if err != nil {
		return err
	}
	fileWriter.Write(encryptedFile)

	keyWriter, err := writer.CreateFormField("encryptedKey")
	if err != nil {
		return err
	}
	keyWriter.Write(encryptedKey)

	contentType := writer.FormDataContentType()
	writer.Close()

	resp, err := http.Post(url, contentType, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func main() {
	// AES密钥生成
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	// 加载接收方公钥
	pubKeyPem, err := ioutil.ReadFile("public.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(pubKeyPem)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 加密文件
	encryptedFile, err := encryptFile("file.txt", key)
	if err != nil {
		panic(err)
	}

	// 加密AES密钥
	encryptedKey, err := encryptAESKey(pubKey.(*rsa.PublicKey), key)
	if err != nil {
		panic(err)
	}

	// 上传文件和加密的AES密钥
	err = uploadFileAndKey("http://192.168.1.6:8080/upload", encryptedFile, encryptedKey)
	if err != nil {
		panic(err)
	}
}
