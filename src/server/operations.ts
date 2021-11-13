import { Nonce, Registration } from '../shared/types';
let crypto = require('crypto').webcrypto as Crypto;

export class CryptoOperations {

  static async hashPublicKey(publicKey: string): Promise<string> {
    let key = new Uint8Array(Buffer.from(publicKey, 'base64'));

    const hash = await crypto.subtle.digest('SHA-256', key);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }

  static async convertPublicKeyToSigningKey(publicKey: string): Promise<CryptoKey> {
    const keyBytes = new Uint8Array(Buffer.from(publicKey, 'base64'));
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

  static async verifyRegistration(registration: Registration, nonce: Nonce, publicKey: string): Promise<boolean> {
    registration = { ...registration };
    if (nonce.value !== registration.nonce || !registration.signature) {
      return false;
    }
    const signature = new Uint8Array(Buffer.from(registration.signature, 'base64'));
    const message = registration.nickname + "." + nonce.value;
    const key = await CryptoOperations.convertPublicKeyToSigningKey(publicKey);
    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      signature,
      new Uint8Array(Buffer.from(message)),
    );
  }
}



