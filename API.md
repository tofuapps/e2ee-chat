# e2ee-chat api
Description + How to use

## Overview

The flow for establishing a connection and communicating between client is as follows:
1. Generate a signing key pair using the RSA Algorithm
2. Register (nickname, signing public key) with the server
3. Identify a target by its signing public key
4. Generate a ephemeral key pair for ECDH
5. Perform a key exchange (ECDH) with the target
6. Derive an AES-256 key
7. Encrypt all messages using the derived key and a randomly generated nonce

More details are found in the sections below.

## Registration
1. Connect to websocket at path `/ws`.
2. Receive `Nonce` from server.
3. Prepare `Registration` object.
4. Sign `sha256(<nickname> + "." + <nonce>)` and attach signature.
5. Return `Registration` to server.

## Key Exchange
1. Prepare `UserInfo` with your keys and nickname.
2. Sign\* and include in `KeyExchangeMessage`, pointing to target.
3. Send `KeyExchangeMessage` to server.

## Message Exchange
1. Prepare `UserMessage` with valid data.
2. Sign\* the message object.
3. Derive secret key with your private key + their public key.
3. Encrypt with derived key into `EncryptedMessage`, pointing to target.
4. Send `EncryptedMessage` to server.

## Acknowledgement Notification
- For any `kind` of message received, reply with a `Notification` acknowledgement setting the `replyTo` param to the value of `kind`.
- If `kind = e2eeMessage`, both `e2eeMessage` and the `kind` value within the encrypted message should be monitored if possible.
  - A client that is able to decrypt the message should respond with `replyTo` set to the decrypted `kind` value.
  - A client that is unable to decrypt the message, and could not forward to the intended target should respond with `replyTo` set to `e2eeMessage`.
- An acknowledgement notification should be signed and encrypted if a communication is already established.

## Algorithms Used
All keys are transmitted in DER-encoded PKIX format encoded with base64.

### Sign and Verify
```
RSASSA-PKCS1-v1_5
modulusLength = 2048
publicExponent = [0x01, 0x00, 0x01]
hash = SHA-256
```

Signing for items marked with \[\*\] is currently performed by doing `sha256(JSON.stringify(<object without signature>))`,
i.e. SHA256 hash of string of JSON object in compact form (no spaces, newlines or indents, e.g. `{"abc":"def","gh":123}`).

### Derive Secret Key
```
ECDH
curve = P-256
```
Note that the secret used by the JS code is currently NOT hashed with SHA256, i.e. it is the raw output of ECDH. 

### Encrypt and Decrypt
(with derived secret key)
```
AES-GCM,
length = 256
```

(A randomly generated 12-byte nonce should be used.)
Note that the nonce and ciphertext should be transmitted in base64 encoded format as well.

## Object details
For details of object specifications, refer to [types.ts](src/shared/types.ts)
