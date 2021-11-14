package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/gorilla/websocket"
)

func GenerateSigningKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Println("Failed to generate signing key:", err)
	}

	return privateKey, &privateKey.PublicKey
}

func ExportRsaPublicKey(key *rsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func Register(nickname string, nonce string) {
	//signingPrivateKey, signingPublicKey := GenerateSigningKeyPair()
	_, signingPublicKey := GenerateSigningKeyPair()
	res, err := ExportRsaPublicKey(signingPublicKey)
	if err != nil {
		log.Fatalln("Registration failed:", err)
	}

	reg := map[string]interface{}{
		"kind": "registration",
		"nickname": nickname,
		"signingPublicKey": res,
		"nonce": nonce,
	}
	b, _ := json.Marshal(reg)

	hasher := sha256.New()
	hasher.Write(b)
	sig := hasher.Sum(nil)
	reg["signature"] = sig
	b, _ = json.Marshal(reg)

	_ = c.WriteMessage(websocket.TextMessage, b)
}
