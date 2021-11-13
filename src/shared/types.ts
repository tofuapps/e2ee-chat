interface Notification {
  kind: "notification";
  replyTo: string;
  success: boolean;
  uuid?: string;
  reason?: string;
  signature?: string;
}

interface Nonce {
  kind: "nonce";
  value: string;
}

interface Registration {
  kind: "registration";
  nickname: string;
  signingPublicKey: string;
  nonce?: string;
  signature?: string;
}

interface UserMessage {
  kind: "message";
  uuid: string;
  message: string;
  timestamp: number;
  signature?: string;
}

interface UserInfo {
  kind: "userInfo";
  nickname: string;
  derivePublicKey?: string;
  signingPublicKey?: string;
  signature?: string;
}

interface KeyExchangeMessage {
  kind: "keyExchange";
  targetPublicKeySHA256?: string;
  info: UserInfo;
}

interface EncryptedMessage {
  kind: "e2eeMessage";
  originPublicKeySHA256?: string;
  targetPublicKeySHA256?: string;
  iv: string;
  ciphertext: string;
}

export {
  Notification,
  Nonce,
  Registration,
  UserMessage,
  UserInfo,
  KeyExchangeMessage,
  EncryptedMessage,
};
