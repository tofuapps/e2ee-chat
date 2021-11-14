package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

func ExportEllipticPublicKey(key *ecdsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

var Nickname string
var SigningPrivateKey *rsa.PrivateKey
var SigningPublicKey *rsa.PublicKey

func Checked(obj map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(obj)
	sig := sha256.Sum256(b)
	obj["signature"] = base64.StdEncoding.EncodeToString(sig[:])
	return obj
}

func Register(nickname string, nonce string) {
	Nickname = nickname

	//signingPrivateKey, signingPublicKey := GenerateSigningKeyPair()
	SigningPrivateKey, SigningPublicKey = GenerateSigningKeyPair()
	res, err := ExportRsaPublicKey(SigningPublicKey)
	if err != nil {
		log.Fatalln("Registration failed:", err)
	}

	b, _ := json.Marshal(Checked(map[string]interface{}{
		"kind": "registration",
		"nickname": nickname,
		"signingPublicKey": res,
		"nonce": nonce,
	}))
	_ = c.WriteMessage(websocket.TextMessage, b)
}

func GenerateDerivedKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatal("Derived key generation failed:", err)
	}
	return privateKey, &privateKey.PublicKey
}

func InitiateKeyExchange(targetPublicKey string) {
	pubKey, _ := ExportRsaPublicKey(SigningPublicKey)

	_, DerivedPublicKey := GenerateDerivedKeyPair()

	res, _ := ExportEllipticPublicKey(DerivedPublicKey)

	userInfo := Checked(map[string]interface{}{
		"kind": "userInfo",
		"nickname": Nickname,
		"derivePublicKey": res,
		"signingPublicKey": pubKey,
	})

	message, _ := json.Marshal(userInfo)
	hashed := sha256.Sum256(message)
	rsa.SignPKCS1v15(rand.Reader, SigningPrivateKey, crypto.SHA256, hashed[:])

	decoded, _ := base64.StdEncoding.DecodeString(targetPublicKey)
	targetHash := sha256.Sum256(decoded)
	keyExchangeMessage := map[string]interface{}{
      "kind": "keyExchange",
	  "targetPublicKeySHA256": base64.StdEncoding.EncodeToString(targetHash[:]),
      "info": userInfo,
    };

	b, _ := json.Marshal(keyExchangeMessage)
	_ = c.WriteMessage(websocket.TextMessage, b)
}
