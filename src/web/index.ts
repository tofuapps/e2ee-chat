import { CryptoOperations } from "./operations";
import { UserMessage } from "../shared/types";
import { log } from "../shared/utils";
import { Socket } from "./Socket";

(() => {
  let socket: Socket | undefined;

  function insertSelfMessage(message: UserMessage) {
    let e = document.getElementById("chat-log") as HTMLUListElement | undefined;
    if (e) {
      let li = document.createElement("li");
      let time = new Date(message?.timestamp);
      let timeStr = time.toLocaleTimeString();
      li.innerText = `[${timeStr}] ${getNickname()}: ${message?.message}`;
      e.appendChild(li);
    }
  }
  function insertUserMessage(message: UserMessage) {
    let nickname = socket?.getTargetUserInfo()?.nickname || "";
    let e = document.getElementById("chat-log") as HTMLUListElement | undefined;
    if (e) {
      let li = document.createElement("li");
      let time = new Date(message?.timestamp);
      let timeStr = time.toLocaleTimeString();
      li.innerText = `[${timeStr}] ${nickname}: ${message?.message}`;
      e.appendChild(li);
    }
  }

  function getNickname(): string {
    let nickname = document.getElementById("nickname") as HTMLInputElement | undefined;
    if (nickname) {
      return nickname.value;
    }
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  async function init() {
    log("init exec");

    socket = new Socket(await CryptoOperations.generateSigningKeyPair());

    socket.newKeyExchangeListener = _ => {
      let tpkEl = document.getElementById("target-public-key-text") as HTMLTextAreaElement | undefined;
      if (tpkEl) {
        tpkEl.value = socket?.getTargetUserInfo()?.signingPublicKey || '';
        tpkEl.readOnly = true;
      }
      let targetNicknameEl = document.getElementById("target-nickname") as HTMLInputElement | undefined;
      if (targetNicknameEl) {
        targetNicknameEl.value = socket?.getTargetUserInfo()?.nickname || '';
        targetNicknameEl.readOnly = true;
      }
      let chatInputEl = document.getElementById("chat-input") as HTMLDivElement | undefined;
      if (chatInputEl) {
        chatInputEl.style.display = "block";
      }
    }


    const pkEl = document.getElementById("public-key-text") as HTMLTextAreaElement | undefined;
    if (pkEl) {
      pkEl.value = await CryptoOperations.exportPublicKeyAsBase64(socket.signingPublicKey);
      pkEl.readOnly = true;
    }

    const tpkEl = document.getElementById("target-public-key-text") as HTMLTextAreaElement | undefined;
    if (tpkEl) {
      tpkEl.value = "";
    }
    const tpkStartChat = document.getElementById("start-chat") as HTMLButtonElement | undefined;
    if (tpkStartChat && tpkEl) {
      let st = async () => {
        try {
          socket?.connectToTargetPublicKey(tpkEl.value);
        } catch (e: any) {
          alert(e);
          tpkEl!.value = "";
          return;
        }
      };
      tpkStartChat.onclick = st;
      tpkEl.onkeyup = (ev: KeyboardEvent) => {
        if (ev.key === "Enter") {
          st();
        }
      };
    }

    const nicknameField = document.getElementById("nickname") as HTMLInputElement | undefined;
    const registerBtn = document.getElementById("register") as HTMLButtonElement | undefined;
    if (registerBtn && nicknameField) {
      let reg = async () => {
        try {
          socket?.setNickname(nicknameField.value);
          registerBtn.disabled = true;
          nicknameField.disabled = true;

          await socket?.register();

          let targetPublicKeyContainer = document.getElementById("target-public-key-container") as HTMLDivElement | undefined;
          if (targetPublicKeyContainer) {
            targetPublicKeyContainer.style.display = "block";
          }
        } catch (e) {
          alert(e);
        }
      };
      registerBtn.onclick = reg;
      nicknameField.onkeydown = (e) => {
        if (e.key === "Enter") {
          reg();
        }
      };
    }


    const chatInput = document.getElementById("chat-input-text") as HTMLInputElement | undefined;
    const chatInputBtn = document.getElementById("chat-input-button") as HTMLButtonElement | undefined;
    if (chatInput && chatInputBtn) {
      let send = async () => {
        if (!chatInput.value) {
          return;
        }
        try {
          await socket?.sendMessage(chatInput.value);
          chatInput.value = "";
        } catch (e) {
          alert(e);
        }
      };
      chatInputBtn.onclick = send;
      chatInput.onkeyup = (e) => {
        if (e.key === "Enter") {
          send();
        }
      };
    }

    socket.newIncomingMessageListener = (message: UserMessage) => {
      insertUserMessage(message);
    }
    socket.newOutgoingMessageListener = (message: UserMessage) => {
      insertSelfMessage(message);
    }

    log("init ready");
  }

  init();

  //Debugging
  (window as any).CryptoOperations = CryptoOperations;
  (window as any).socket = socket;

})();
