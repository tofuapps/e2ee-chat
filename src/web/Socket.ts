import {EncryptedMessage, KeyExchangeMessage, Nonce, Notification, Registration, UserInfo, UserMessage} from "../shared/types";
import {log, uuidv4} from "../shared/utils";
import {CryptoOperations} from "./operations";

export class Socket {
  private ws: WebSocket | undefined;
  private nonce: Nonce | undefined;
  private nickname: string | undefined;
  private registered: boolean = false;

  private notificationPendingHandlers: { [key: string]: Set<(e: Notification) => void> } = {};

  readonly signingPublicKey: CryptoKey;
  readonly signingPrivateKey: CryptoKey;

  private derivePublicKey: CryptoKey | undefined;
  private derivePrivateKey: CryptoKey | undefined;

  private targetUserInfo: UserInfo | undefined;
  private targetDerivePublicKey: CryptoKey | undefined;
  private targetSigningPublicKey: CryptoKey | undefined;

  constructor(signingKeyPair: CryptoKeyPair) {
    if (!signingKeyPair || !signingKeyPair.privateKey || !signingKeyPair.publicKey) {
      throw new Error("Invalid signing key pair!");
    }
    this.signingPrivateKey = signingKeyPair.privateKey;
    this.signingPublicKey = signingKeyPair.publicKey;
    this.connect();
  }

  public connect() {
    if (this.isConnected()) {
      return;
    }
    let wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    let wsUrl = `${wsProtocol}//${window.location.host}/ws`;
    this.ws = this.initWebsocketConnection(wsUrl);
  }
  public disconnect() {
    this.ws?.close();
    this.ws = undefined;
    this.nonce = undefined;
    this.registered = false;
  }
  public isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private initWebsocketConnection(url: string): WebSocket {
    const webSocket = new WebSocket(url);
    webSocket.onopen = () => {
      log("Connected to server at " + webSocket.url);
    };
    webSocket.onmessage = async (event) => {
      let data = event.data;
      let json = JSON.parse(data);

      log("Received", json);
      this.dispatchToHandler(json);
    };
    webSocket.onclose = () => {
      log("Disconnected from server!");
      alert("Disconnected. Reload page to reconnect.");
    };
    webSocket.onerror = (event) => {
      log("Error:", event);
    };
    return webSocket;
  }

  //
  // MARK: Incoming Message Internal Dispatch Helper
  //
  private async dispatchToHandler(json: any) {
    if (json.kind === "nonce" && json.value) {
      this.nonce = json as Nonce;
    } else if (json.kind === "notification") {
      let notification = json as Notification;
      await this.handleNotification(notification);
    } else if (json.kind === "keyExchange") {
      let keyExchange = json as KeyExchangeMessage;
      await this.handleKeyExchange(keyExchange);
    } else if (json.kind === "message") {
      let message = json as UserMessage;
      await this.handleIncomingMessage(message);
    } else if (json.kind === "e2eeMessage") {
      let encryptedMessage = json as EncryptedMessage;
      await this.handleEncryptedMessage(encryptedMessage).catch(e => log("error processing:", e?.message))
    } else {
      log("Unknown message not handled:", json);
    }
  }

  private async handleEncryptedMessage(message: EncryptedMessage) {
    if (!this.derivePublicKey || !this.derivePrivateKey) {
      throw new Error("No derivation key pair!");
    }
    if (!this.signingPublicKey || !this.signingPrivateKey) {
      throw new Error("No signing key pair!");
    }

    let selfPrivateKey = this.derivePrivateKey;
    let sourcePublicKey = this.targetDerivePublicKey;

    if (!sourcePublicKey) {
      throw new Error("Message source public key not found!");
    }
    if (!selfPrivateKey) {
      throw new Error("Own private key not found!");
    }

    let decrypted = await CryptoOperations.decryptMessage(message, selfPrivateKey, sourcePublicKey);
    log("Decrypted message:", decrypted);
    this.dispatchToHandler(decrypted);
    return;
  }

  //
  // MARK: Outgoing Message Internal Dispatch Helper
  //
  private async send(data: any, listenForReply?: boolean | string): Promise<Notification | undefined> {
    return new Promise((resolve, reject) => {
      if (!this.ws) {
        reject(new Error("Not connected to server!"));
        return;
      }
      if (listenForReply !== false) {
        //setup notification listener
        let halted = false;
        let replyToDirect = data.kind;
        let replyToIndirect = (typeof listenForReply === "string") ? listenForReply : undefined;
        let notificationHandler: ((notification: Notification) => void) | undefined;
        let clear = () => {
          halted = true;
          if (notificationHandler) {
            this.notificationPendingHandlers[replyToDirect]?.delete(notificationHandler);

            if (replyToIndirect)
              this.notificationPendingHandlers[replyToIndirect]?.delete(notificationHandler);
          }
        };
        let timeout = setTimeout(() => {
          clear();
          reject("Request timed out, no reply received for " + (replyToIndirect || replyToDirect));
        }, 3000);

        notificationHandler = (notification: Notification) => {
          if (halted) {
            return;
          }
          clearTimeout(timeout);
          clear();

          resolve(notification);
        }

        if (!this.notificationPendingHandlers[replyToDirect]) {
          this.notificationPendingHandlers[replyToDirect] = new Set();
        }
        if (replyToIndirect && !this.notificationPendingHandlers[replyToIndirect]) {
          this.notificationPendingHandlers[replyToIndirect] = new Set();
        }
        this.notificationPendingHandlers[replyToDirect].add(notificationHandler);
        if (replyToIndirect) this.notificationPendingHandlers[replyToIndirect]?.add(notificationHandler);
      }

      //send data
      if (typeof data === "string") {
        this.ws.send(data);
      } else if (data instanceof String) {
        this.ws.send(data.toString());
      } else {
        this.ws.send(JSON.stringify(data));
      }

      if (listenForReply === false) {
        resolve(undefined);
        return;
      }

    });
  }

  private async sendEncrypted(data: any, listenForReply?: boolean | string, altTargetInfo?: UserInfo): Promise<Notification | undefined> {
    if (!data) return;

    if (!this.derivePublicKey || !this.derivePrivateKey) {
      throw new Error("No derivation key pair!");
    }
    if (!this.signingPublicKey || !this.signingPrivateKey) {
      throw new Error("No signing key pair!");
    }

    let selfPrivateKey = this.derivePrivateKey;
    let targetPublicKey = altTargetInfo?.derivePublicKey || this.targetDerivePublicKey;

    if (!targetPublicKey) {
      throw new Error("No target derivation public key!");
    }

    if (!selfPrivateKey) {
      throw new Error("No private key for self!");
    }

    let targetSigningPublicKey = altTargetInfo?.derivePublicKey || this.targetSigningPublicKey;
    if (!targetSigningPublicKey) {
      throw new Error("No target public key!");
    }

    let encrypted = await CryptoOperations.encryptMessage(data, selfPrivateKey, targetPublicKey);
    let targetPublicKeySHA256 = await CryptoOperations.hashPublicKey(targetSigningPublicKey);
    encrypted.targetPublicKeySHA256 = targetPublicKeySHA256;

    let kind = listenForReply !== false ? data.kind : false;
    if (listenForReply !== false && typeof listenForReply === "string") {
      kind = listenForReply;
    }
    return await this.send(encrypted, kind);
  }

  private async sendNotification(replyTo: string, success: boolean, reason?: string, uuid?: string, altTargetInfo?: UserInfo) {
    let notification: Notification = {
      kind: 'notification',
      replyTo,
      success,
      uuid,
      reason
    }
    await this.sendEncrypted(notification, false, altTargetInfo);
  }

  //
  // MARK: Incoming Message Internal Handlers
  //
  private async handleNotification(notification: Notification) {
    let handlers = this.notificationPendingHandlers[notification.replyTo || ''];
    if (handlers) {
      handlers.forEach((handler) => {
        handler(notification);
      });
      handlers.clear();
    }
    this.newNotificationListener?.(notification);
  }

  private async handleKeyExchange(keyExchange: KeyExchangeMessage) {
    log("key exchange: received from target");

    if (this.targetUserInfo && keyExchange.info.signingPublicKey !== this.targetUserInfo.signingPublicKey) {
      this.sendNotification(keyExchange.kind, false, "Unable to connect due to an already existing connection.", undefined, keyExchange.info);
      return;
    }
    if (!keyExchange.info.signingPublicKey || !keyExchange.info.derivePublicKey) {
      throw new Error("Error: Received key exchange message without public key!");
    }
    if (!CryptoOperations.verify(keyExchange.info, keyExchange.info.signingPublicKey)) {
      throw new Error("Error: Received key exchange message with invalid signature!");
    }

    let shouldReturnExchange = false;
    if (this.targetUserInfo === undefined) {
      shouldReturnExchange = true;
    }

    this.targetUserInfo = keyExchange.info;
    this.targetSigningPublicKey = await CryptoOperations.importSigningPublicKeyFromBase64(keyExchange.info.signingPublicKey);
    this.targetDerivePublicKey = await CryptoOperations.importDerivePublicKeyFromBase64(keyExchange.info.derivePublicKey);

    this.sendNotification(keyExchange.kind, true);

    if (shouldReturnExchange) {
      this.sendKeyExchange();
    }

    this.newKeyExchangeListener?.(keyExchange);
  }

  private async handleIncomingMessage(message: UserMessage) {
    if (this.targetSigningPublicKey && !CryptoOperations.verify(message, this.targetSigningPublicKey)) {
      throw new Error("Error: Received message with invalid signature!");
    }

    if (Math.abs(message.timestamp - Date.now()) > 1000 * 60 * 5) {
      throw new Error("Error: Received message with invalid timestamp (deviation of more than 5 minutes)!");
    }

    //TODO: Process and cache data here

    try {
      this.sendNotification(message.kind, true, undefined, message.uuid);
    } catch (e) {
      log("Error:", e);
    }

    // Notify listeners
    this.newIncomingMessageListener?.(message);
  }

  //
  // MARK: Registration and Setup Helpers
  //

  public getNickname(): string | undefined {
    return this.nickname;
  }
  public setNickname(nickname: string) {
    if (this.registered) {
      throw new Error("Error: Cannot set nickname after registration!");
    }
    this.nickname = nickname;
  }

  public async register(): Promise<void> {
    let nickname = this.getNickname();

    if (!this.nonce || !this.nonce.value) {
      throw new Error("No nonce received yet!");
    }
    if (!nickname) {
      throw new Error("No nickname set!");
    }

    let registerMessage: Registration = {
      kind: "registration",
      nickname: nickname,
      signingPublicKey: await CryptoOperations.exportPublicKeyAsBase64(this.signingPublicKey),
    };

    registerMessage = await CryptoOperations.signRegistration(
      registerMessage, this.nonce, this.signingPrivateKey
    );

    log("Sending registration message");
    let result = await this.send(registerMessage);
    if (!result?.success) {
      throw new Error("Registration failed: " + result?.reason);
    } else {
      this.registered = true;
    }
  }


  public async connectToTargetPublicKey(publicKey: string) {
    this.targetSigningPublicKey = await CryptoOperations.importSigningPublicKeyFromBase64(publicKey);
    this.sendKeyExchange();
  }

  public getTargetUserInfo(): UserInfo | undefined {
    if (this.targetUserInfo) {
      return {...this.targetUserInfo};
    } else {
      return undefined;
    }
  }

  public getDeriveKeyPair(): CryptoKeyPair {
    return {
      publicKey: this.derivePublicKey,
      privateKey: this.derivePrivateKey
    };
  }

  //
  // MARK: Incoming Message Listeners
  //
  public newIncomingMessageListener: ((message: UserMessage) => void) | undefined;
  public newOutgoingMessageListener: ((message: UserMessage) => void) | undefined;
  public newNotificationListener: ((notification: Notification) => void) | undefined;
  public newKeyExchangeListener: ((keyExchange: KeyExchangeMessage) => void) | undefined;

  //
  // MARK: Outgoing Message Helper
  //
  public async sendKeyExchange() {
    if (!this.signingPublicKey || !this.signingPrivateKey) {
      throw new Error("No signing key pair!");
    }
    if (!this.targetSigningPublicKey) {
      throw new Error("No target public key!");
    }

    let deriveKeyPair = await CryptoOperations.generateDeriveKeyPair();
    if (!deriveKeyPair || !deriveKeyPair.publicKey || !deriveKeyPair.privateKey) {
      throw new Error("Cannot create derivation key pair!");
    }

    let nickname = this.getNickname();
    if (!nickname) {
      throw new Error("No nickname!");
    }

    this.derivePrivateKey = deriveKeyPair.privateKey;
    this.derivePublicKey = deriveKeyPair.publicKey;

    let signingPublicKeyString = await CryptoOperations.exportPublicKeyAsBase64(this.signingPublicKey);
    let derivePublicKeyString = await CryptoOperations.exportPublicKeyAsBase64(deriveKeyPair.publicKey);

    let userInfo: UserInfo = {
      kind: "userInfo", nickname,
      signingPublicKey: signingPublicKeyString,
      derivePublicKey: derivePublicKeyString
    };
    userInfo = await CryptoOperations.sign(userInfo, this.signingPrivateKey);

    let keyExchangeMessage: KeyExchangeMessage = {
      kind: "keyExchange",
      targetPublicKeySHA256: await CryptoOperations.hashPublicKey(this.targetSigningPublicKey),
      info: userInfo,
    };

    log("key exchange: sending to target");
    let result = await this.send(keyExchangeMessage);
    if (!result?.success) {
      throw new Error("Key exchange failed: " + result?.reason);
    }
  }

  public async sendMessage(msg: string) {
    let message: UserMessage = {
      kind: "message",
      uuid: uuidv4(),
      message: msg,
      timestamp: Date.now(),
    };
    message = await CryptoOperations.sign(message, this.signingPrivateKey);

    //TODO: Process and cache data here

    let result = await this.sendEncrypted(message);
    if (!result?.success) {
      throw new Error("Message failed to send: " + result?.reason);
    }
    this.newOutgoingMessageListener?.(message);
  }

}
