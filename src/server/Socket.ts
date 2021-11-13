import { WebSocket, Server } from 'ws';
import { Nonce, Notification, Registration, UserInfo } from '../shared/types';
import * as crypto from 'crypto';
import { CryptoOperations } from './operations';

export class UserSocket {
  private socket: WebSocket;
  private server: Server;
  private nickname: string | undefined;
  private publicKey: string | undefined;
  private publicKeySHA256: string | undefined;

  constructor(socket: WebSocket, server: Server) {
    this.socket = socket;
    this.server = server;

    this.challenge().then(this.onReady.bind(this)).catch(this.onFailure.bind(this));
  }

  public onReadyHandler: () => Promise<void> = async () => {};

  private async onReady() {
    console.log("client %s registered as %s", this.getPublicKeySHA256(), this.getNickname());
    this.socket.once('close', () => {
      let keyHash = this.getPublicKeySHA256();
      if (keyHash) {
        console.log("client %s disconnected", keyHash);
      } else {
        console.log("unregistered client disconnected");
      }
      this.clearData();
    });

    await this.onReadyHandler().then(() => {
      this.sendNotification(
        'registration',
        true
      );
    }).catch((e) => {
      this.sendNotification(
        'registration',
        false,
        e.message
      );
    });
  }

  private onFailure(error: Error) {
    console.error("registration failure", error);
    this.sendNotification(
      'registration',
      false,
      error.message || 'Invalid registration response'
    );
    this.socket.close();
  };

  private async challenge() : Promise<void> {
    return new Promise((resolve, reject) => {
      const nonce : Nonce = {
        kind: 'nonce',
        value: crypto.randomBytes(16).toString('hex')
      }
      this.socket.send(JSON.stringify(nonce));
      this.socket.once('message', async (message: string) => {
        const response = JSON.parse(message) as Partial<Registration>;
        if (response.kind === 'registration' && response.nonce === nonce.value) {
          let nickname = response.nickname;
          let signature = response.signature;
          let publicKey = response.signingPublicKey;

          if (!(nickname && signature && publicKey)) {
            reject(Error('Invalid registration response'));
            return;
          }

          let verification = CryptoOperations.verifyRegistration(response as Registration, nonce, publicKey);
          if (!verification) {
            reject(Error('Invalid registration response'));
            return;
          }

          let publicKeySHA256 = await CryptoOperations.hashPublicKey(publicKey)

          this.nickname = nickname;
          this.publicKey = publicKey;
          this.publicKeySHA256 = publicKeySHA256;

          resolve();
        } else {
          reject(Error('Invalid registration response'));
        }
      });
    });
  }

  private clearData() {
    this.nickname = undefined;
    this.publicKey = undefined;
    this.publicKeySHA256 = undefined;
  }

  public send(data: any) {
    if (typeof data === "string") {
      this.socket.send(data);
    } else if (data instanceof String) {
      this.socket.send(data.toString());
    } else {
      this.socket.send(JSON.stringify(data));
    }
  }

  public sendNotification(replyTo: string, success: boolean, reason?: string) {
    let notification: Notification = {
      kind: 'notification',
      replyTo: replyTo,
      success: success,
      reason: reason
    }
    this.send(notification);
  }

  public getUserInfo(): UserInfo | undefined {
    if (!this.nickname || !this.publicKey) {
      return undefined;
    }
    return {
      kind: 'userInfo',
      nickname: this.nickname,
      signingPublicKey: this.publicKey
    }
  }

  public getNickname(): string | undefined {
    return this.nickname;
  }
  public getPublicKey(): string | undefined {
    return this.publicKey;
  }
  public getPublicKeySHA256(): string | undefined {
    return this.publicKeySHA256;
  }
  public getPublicKeyShortSHA256(): string | undefined {
    if (this.publicKeySHA256) {
      return this.publicKeySHA256.substring(0, 8);
    }
    return undefined;
  }
}
