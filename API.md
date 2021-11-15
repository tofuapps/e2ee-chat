# e2ee-chat api
Description + How to use

## Overview

The flow for establishing a connection and communicating between client is as follows:
1. Generate a signing key pair using the RSA algorithm.
2. Register (nickname, signing public key) with the server and sign.
3. Identify a target by its signing public key.
4. Generate a ephemeral key pair for ECDH.
5. Perform a key exchange (ECDH) with the target.
6. Derive an AES-256 key.
7. Encrypt all messages using the derived key.

More details are found in the sections below.

## Registration
1. Connect to websocket at path `/ws`.
2. Receive `Nonce` from server.
3. Prepare `Registration` object.
4. Sign `sha256(<nickname string> + "." + <nonce base64 string>)` with RSA PKCS#1 v1.5 and attach signature.
5. Return `Registration` to server.
6. Wait for `NotificationReceipt` reply.

## Key Exchange
1. Prepare `UserInfo` with your RSA signing and EC ephemeral derivation keys and nickname (more details below).
2. Sign\* and include in `KeyExchangeMessage`, pointing to target.
3. Send `KeyExchangeMessage` to server.
4. Wait for other party to return you with a `KeyExchangeMessage` as well.
5. Verify signature and send an encrypted `NotificationReceipt`.
6. Wait for `NotificationReceipt` reply.

## Message Exchange
1. Prepare `UserMessage` with valid data, including a randomly generated UUID and timestamp (UNIX).
2. Sign\* the message object.
3. Obtain an AES-256 secret key by hashing the derived output of your private key + their public key (ECDH, see details below)
3. Encrypt message with derived key with AES-GCM (96 bit+ initialization vector) into `EncryptedMessage`, pointing to target.
4. Send `EncryptedMessage` to server.
5. Wait for `NotificationReceipt` acknowledgement. This acknowledgement should also reference the UUID of the message.

## Acknowledgement Notification
- For any `kind` of message received, reply with a `NotificationReceipt` acknowledgement, setting the `replyTo` param to the value of `kind`.
- If the original message's `kind = e2eeMessage`:
  - a client that is able to decrypt the message should respond with `replyTo` set to the decrypted `kind` value.
  - a client (or the server) that is unable to decrypt the message, and could not forward to the intended target should respond with `replyTo` set to `e2eeMessage`.
- An acknowledgement notification should be **signed** and **encrypted** if a communication is already established.

## Algorithms Used
Important General Notes:
- All public keys are transmitted in base64 encoding of the raw bytes in ASN.1-DER-encoded X.509 SubjectPublicKeyInfo form.
- All SHA256 operations on public keys are performed on the raw bytes (not the base64 encoded form).

### Sign and Verify
```
RSASSA-PKCS1-v1_5
modulus length = 2048
public exponent = 65537 (0x010001)
hash = SHA-256
```

Signing for items marked with \[\*\] is currently performed by doing `sha256(JSON.stringify(<object without signature>))`,
i.e. SHA256 hash of string of JSON object in compact form (no spaces, newlines or indents, e.g. `{"abc":"def","gh":123}`).

### Derive Secret Key
```
ECDH
curve = P-256
```
1. Derive with self private key + their public key
2. Derivation output hashed with SHA256
3. Result used as AES-256-GCM secret key

### Encrypt and Decrypt
(with derived secret key)
```
AES-256-GCM
iv length = 96 bits+
auth tag length = 128 bits
```
Note that the initialization vector (to be randomly generated) and ciphertext should be transmitted in base64 encoded format as well.

## Object details
For details of object specifications, refer to [types.ts](src/shared/types.ts)
