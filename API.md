# e2ee-chat api
Description of how the current API works, I guess

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
### Encrypt and Decrypt
(with derived secret key)
```
AES-GCM,
length = 256
```

## Object details
For details of object specifications, refer to [types.ts](src/shared/types.ts)
