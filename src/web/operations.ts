import { EncryptedMessage, Nonce, Registration } from '../shared/types';

export class CryptoOperations {
  static async generateEncryptKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}
      },
      true,
      ["encrypt", "decrypt"]
    );
  }
  static async generateDeriveKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      ["deriveKey"]
    );
  }
  static async generateSigningKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}
      },
      true,
      ["sign", "verify"]
    );
  }
  static async deriveSecretKey(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
    let key = await crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: publicKey
      },
      privateKey,
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );
    let raw = await crypto.subtle.exportKey('raw', key);
    let hash = await crypto.subtle.digest('SHA-256', raw);
    key = await crypto.subtle.importKey(
      'raw',
      hash,
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );
    return key;
  }
  static async hashPublicKey(publicKey: string | CryptoKey): Promise<string> {
    let key;
    if (publicKey instanceof CryptoKey) {
      key = await crypto.subtle.exportKey('spki', publicKey);
    } else {
      key = new Uint8Array(atob(publicKey).split('').map(c => c.charCodeAt(0)));
    }

    const hash = await crypto.subtle.digest('SHA-256', key);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }

  static async signRegistration(registration: Registration, nonce: Nonce, privateKey: CryptoKey): Promise<Registration> {
    registration = { ...registration };
    delete registration.nonce;
    delete registration.signature;

    registration.nonce = nonce.value;

    const message = registration.nickname + "." + nonce.value;
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      new TextEncoder().encode(message)
    );
    registration.signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    return registration;
  }

  static async sign<T>(message: T, privateKey: CryptoKey): Promise<T> {
    message = { ...message };
    if ((message as any).signature)
      delete (message as any).signature;

    const messageString = JSON.stringify(message);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      new TextEncoder().encode(messageString)
    );
    (message as any).signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    return message;
  }

  static async verify<T>(message: T, publicKey: string | CryptoKey): Promise<boolean> {
    message = { ...message };
    if (!(message as any).signature) {
      return false;
    }
    const signature = new Uint8Array(atob((message as any).signature).split('').map(c => c.charCodeAt(0)));
    delete (message as any).signature;
    const messageString = JSON.stringify(message);
    const key = publicKey instanceof CryptoKey ? publicKey : await CryptoOperations.importSigningPublicKeyFromBase64(publicKey);
    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      signature,
      new TextEncoder().encode(messageString)
    );
  }

  static async encryptMessage(message: any, selfPrivateKey: CryptoKey, targetPublicKey: string | CryptoKey): Promise<EncryptedMessage> {
    targetPublicKey = targetPublicKey instanceof CryptoKey ? targetPublicKey : await CryptoOperations.importDerivePublicKeyFromBase64(targetPublicKey);

    const intermediateSecretKey = await CryptoOperations.deriveSecretKey(selfPrivateKey, targetPublicKey);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      intermediateSecretKey,
      new TextEncoder().encode(JSON.stringify(message)),
    );

    return {
      kind: 'e2eeMessage',
      targetPublicKeySHA256: await CryptoOperations.hashPublicKey(targetPublicKey),
      iv           : btoa(String.fromCharCode(...iv)),
      ciphertext   : btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    };
  }

  static async decryptMessage(message: EncryptedMessage, selfPrivateKey: CryptoKey, sourcePublicKey: string | CryptoKey): Promise<any> {
    sourcePublicKey = sourcePublicKey instanceof CryptoKey ? sourcePublicKey : await CryptoOperations.importDerivePublicKeyFromBase64(sourcePublicKey);

    const intermediateSecretKey = await CryptoOperations.deriveSecretKey(selfPrivateKey, sourcePublicKey);

    const iv = new Uint8Array(atob(message.iv).split('').map(c => c.charCodeAt(0)));
    const ciphertext = new Uint8Array(atob(message.ciphertext).split('').map(c => c.charCodeAt(0)));

    const decryptedCiphertext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      intermediateSecretKey,
      ciphertext,
    );

    return JSON.parse(new TextDecoder().decode(decryptedCiphertext));
  }

  static async exportKeyPairAsBase64(keyPair: CryptoKeyPair): Promise<{privateKey: string, publicKey: string}> {
    if (!keyPair.publicKey || !keyPair.privateKey) throw new Error("incomplete key pair");
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    return {
      privateKey: btoa(new Uint8Array(privateKey).reduce((data, byte) => data + String.fromCharCode(byte), "")),
      publicKey: btoa(new Uint8Array(publicKey).reduce((data, byte) => data + String.fromCharCode(byte), ""))
    };
  }

  static async exportPublicKeyAsBase64(publicKey: CryptoKey): Promise<string> {
    const publicKeyBytes = await crypto.subtle.exportKey("spki", publicKey);
    return btoa(new Uint8Array(publicKeyBytes).reduce((data, byte) => data + String.fromCharCode(byte), ""));
  }

  static async importSigningKeyPairFromBase64(base64: {privateKey: string, publicKey: string}): Promise<CryptoKeyPair> {
    const privateKeyData = new Uint8Array(atob(base64.privateKey).split("").map(c => c.charCodeAt(0)));
    const publicKeyData = new Uint8Array(atob(base64.publicKey).split("").map(c => c.charCodeAt(0)));
    const privateKey = await crypto.subtle.importKey("pkcs8", privateKeyData, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, true, ["sign"]);
    const publicKey = await crypto.subtle.importKey("spki", publicKeyData, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, true, ["verify"]);
    return {
      privateKey,
      publicKey
    };
  }

  static async importDeriveKeyPairFromBase64(base64: {privateKey: string, publicKey: string}): Promise<CryptoKeyPair> {
    const privateKeyData = new Uint8Array(atob(base64.privateKey).split("").map(c => c.charCodeAt(0)));
    const publicKeyData = new Uint8Array(atob(base64.publicKey).split("").map(c => c.charCodeAt(0)));
    const privateKey = await crypto.subtle.importKey("pkcs8", privateKeyData, {name: "ECDH", namedCurve: "P-256"}, true, ["deriveKey"]);
    const publicKey = await crypto.subtle.importKey("spki", publicKeyData, {name: "ECDH", namedCurve: "P-256"}, true, []);
    return {
      privateKey,
      publicKey
    };
  }

  static async importEncryptKeyPairFromBase64(base64: {privateKey: string, publicKey: string}): Promise<CryptoKeyPair> {
    const privateKeyData = new Uint8Array(atob(base64.privateKey).split("").map(c => c.charCodeAt(0)));
    const publicKeyData = new Uint8Array(atob(base64.publicKey).split("").map(c => c.charCodeAt(0)));
    const privateKey = await crypto.subtle.importKey("pkcs8", privateKeyData, {name: "RSA-OAEP", hash: {name: "SHA-256"}}, true, ["encrypt"]);
    const publicKey = await crypto.subtle.importKey("spki", publicKeyData, {name: "RSA-OAEP", hash: {name: "SHA-256"}}, true, ["decrypt"]);
    return {
      privateKey,
      publicKey
    };
  }

  static async importEncryptPublicKeyFromBase64(publicKey: string): Promise<CryptoKey> {
    const keyBytes = new Uint8Array(atob(publicKey).split('').map(c => c.charCodeAt(0)));
    const keyFormat = 'spki';
    const keyUsages: KeyUsage[] = ['encrypt'];
    const keyAlgorithm = { name: 'RSA-OAEP', hash: 'SHA-256' };
    const cryptoKey = await crypto.subtle.importKey(
      keyFormat,
      keyBytes,
      keyAlgorithm,
      true,
      keyUsages,
    );
    return cryptoKey;
  }
  static async importDerivePublicKeyFromBase64(publicKey: string): Promise<CryptoKey> {
    const keyBytes = new Uint8Array(atob(publicKey).split('').map(c => c.charCodeAt(0)));
    const keyFormat = 'spki';
    const keyUsages: KeyUsage[] = [];
    const keyAlgorithm = { name: 'ECDH', namedCurve: 'P-256' };
    const cryptoKey = await crypto.subtle.importKey(
      keyFormat,
      keyBytes,
      keyAlgorithm,
      true,
      keyUsages,
    );
    return cryptoKey;
  }
  static async importSigningPublicKeyFromBase64(publicKey: string): Promise<CryptoKey> {
    const keyBytes = new Uint8Array(atob(publicKey).split('').map(c => c.charCodeAt(0)));
    const keyFormat = 'spki';
    const keyUsages: KeyUsage[] = ['verify'];
    const keyAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    const cryptoKey = await crypto.subtle.importKey(
      keyFormat,
      keyBytes,
      keyAlgorithm,
      true,
      keyUsages,
    );
    return cryptoKey;
  }
}



