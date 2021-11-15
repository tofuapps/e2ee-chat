package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
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
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func ExportEllipticPublicKey(key *ecdsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func ImportEllipticPublicKey(enc string) (*ecdsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return key.(*ecdsa.PublicKey), nil
}

var Nickname string
var SigningPrivateKey *rsa.PrivateKey
var SigningPublicKey *rsa.PublicKey
var DerivePrivateKey *ecdsa.PrivateKey
var DerivePublicKey *ecdsa.PublicKey
var UserInfo map[string]interface{}

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

	log.Println("PublicKey:", res)
	log.Println()
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

func Sign(obj map[string]interface{}) map[string]interface{} {
	delete(obj, "signature")
	message, _ := json.Marshal(obj)
	hashed := sha256.Sum256(message)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, SigningPrivateKey, crypto.SHA256, hashed[:])
	obj["signature"] = base64.StdEncoding.EncodeToString(sig)
	return obj
}

var TargetHash string
var TargetDerivePublicKey *ecdsa.PublicKey

func PrepareForKeyExchange() {
	pubKey, _ := ExportRsaPublicKey(SigningPublicKey)

	DerivePrivateKey, DerivePublicKey = GenerateDerivedKeyPair()

	res, _ := ExportEllipticPublicKey(DerivePublicKey)

	UserInfo = Checked(map[string]interface{}{
		"kind": "userInfo",
		"nickname": Nickname,
		"derivePublicKey": res,
		"signingPublicKey": pubKey,
	})
}

func HandleKeyExchange(targetUserInfo map[string]interface{}) {
	if len(UserInfo) == 0 {
		PrepareForKeyExchange()
		targetSigningPublicKey := targetUserInfo["signingPublicKey"].(string)
		PerformKeyExchange(targetSigningPublicKey)
	}

	derivePublicKey := targetUserInfo["derivePublicKey"].(string)
	TargetDerivePublicKey, _ = ImportEllipticPublicKey(derivePublicKey)

	message := map[string]interface{}{
      "kind": "notification",
	  "replyTo": "keyExchange",
	  "success": "true",
	}
	SendMessage(Encrypt(message))
}

func PerformKeyExchange(targetSigningPublicKey string) {
	UserInfo = Sign(UserInfo)

	decoded, _ := base64.StdEncoding.DecodeString(targetSigningPublicKey)
	hashed := sha256.Sum256(decoded)
	TargetHash = base64.StdEncoding.EncodeToString(hashed[:])
	keyExchangeMessage := map[string]interface{}{
		"kind": "keyExchange",
		"targetPublicKeySHA256": TargetHash,
		"info": UserInfo,
	};

	b, _ := json.Marshal(keyExchangeMessage)
	_ = c.WriteMessage(websocket.TextMessage, b)
}

func DeriveKey() cipher.AEAD {
	// ecdh algorithm
	x, _ := TargetDerivePublicKey.Curve.ScalarMult(
		TargetDerivePublicKey.X,
		TargetDerivePublicKey.Y,
		DerivePrivateKey.D.Bytes(),
	)
	shared := sha256.Sum256(x.Bytes()) // warning: JS is super weird and doesn't hash this

	// generate AES key
	block, _ := aes.NewCipher(shared[:])
	aesgcm, _ := cipher.NewGCM(block)
	return aesgcm
}

func Encrypt(message map[string]interface{}) map[string]interface{} {
	plaintext, _ := json.Marshal(message)
	aesgcm := DeriveKey()
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalln(err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return map[string]interface{}{
      "kind": "e2eeMessage",
      "targetPublicKeySHA256": TargetHash,
      "iv": base64.StdEncoding.EncodeToString(nonce),
      "ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
    }
}

func Decrypt(message map[string]interface{}) map[string]interface{} {
	ciphertext, _ := base64.StdEncoding.DecodeString(message["ciphertext"].(string))
	aesgcm := DeriveKey()
	nonce, _ := base64.StdEncoding.DecodeString(message["iv"].(string))

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	var res map[string]interface{}
	if err := json.Unmarshal(plaintext, &res); err != nil {
		panic(err.Error())
	}
	return res;
}

func SendMessage(message map[string]interface{}) {
	b, _ := json.Marshal(message)
	_ = c.WriteMessage(websocket.TextMessage, b)
}
