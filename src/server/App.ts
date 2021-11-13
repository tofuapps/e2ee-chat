import express, { Request, Response } from 'express';
import bodyparser from 'body-parser';
import path from 'path';
import http from 'http';
import ws from 'ws';
import { EncryptedMessage, KeyExchangeMessage } from '../shared/types';
import { UserSocket } from './Socket';

export class App {
  readonly app: express.Application;
  readonly server: http.Server;
  readonly wss: ws.Server;
  readonly port: number;

  private userClients: Set<UserSocket> = new Set();
  private userPublicKeySHA256ToClient: Map<string, Set<UserSocket>> = new Map();

  constructor(port: number) {
    this.app = express();
    this.server = http.createServer(this.app);
    this.wss = new ws.Server({ noServer: true });

    this.port = isNaN(port) ? 8080 : port;

    this.initializeMiddlewares();
  }

  private initializeMiddlewares() {
    let staticPath = path.join(__dirname, '..', 'web');
    console.log("serving static contents from", staticPath);
    this.app.use(express.static(staticPath));
    this.app.use(bodyparser.urlencoded({extended: true}));
    this.app.use(bodyparser.json());
  }

  private listenWebsocket() {
    this.wss.on('connection', (socket: ws.WebSocket) => {
      const client = new UserSocket(socket, this.wss);
      client.onReadyHandler = async () => {
        this.userClients.add(client);

        let keyHash = client.getPublicKeySHA256();
        if (!keyHash) {
          return;
        }

        let initialSet = this.userPublicKeySHA256ToClient.get(keyHash);
        if (initialSet === undefined) {
          initialSet = new Set();
          this.userPublicKeySHA256ToClient.set(keyHash, initialSet);
        }
        if (initialSet.size > 0) {
          console.log("attemped registration with duplicate public key");
          throw new Error("A user with the given public key is already online.");
        }
        initialSet.add(client);
      };

      socket.on('message', async (message: string) => {
        let json = JSON.parse(message);
        console.log("< received " + json.kind);
        this.handleExchangeBridge(json, client);
      });

      socket.on('close', async () => {
        this.userClients.delete(client);

        let keyHash = client.getPublicKeySHA256();
        if (!keyHash) {
          return;
        }

        let initialSet = this.userPublicKeySHA256ToClient.get(keyHash);
        if (initialSet !== undefined) {
          initialSet.delete(client);
          if (initialSet.size === 0) {
            this.userPublicKeySHA256ToClient.delete(keyHash);
          }
        }
      });

    });
  }

  private handleExchangeBridge(data: any, client: UserSocket) {
    if (data.kind == "e2eeMessage" || data.kind == "keyExchange") {

      let exchangeData = data as Partial<EncryptedMessage | KeyExchangeMessage>;
      let target = exchangeData.targetPublicKeySHA256;

      if (exchangeData.kind == "e2eeMessage" && exchangeData.originPublicKeySHA256 !== client.getPublicKeySHA256()) {
        exchangeData.originPublicKeySHA256 = client.getPublicKeySHA256();
      }

      if (target === undefined) {
        return;
      }

      let targetSet = this.userPublicKeySHA256ToClient.get(target);
      if (targetSet === undefined) {
        console.log("exchange target not found");
        client.sendNotification(data.kind, false, "The user with the given public key is not online.");
        return;
      }
      targetSet.forEach(targetClient => {
        console.log("forwarding %s (%s) -> (%s)", data.kind, client.getPublicKeyShortSHA256(), targetClient.getPublicKeyShortSHA256());
        targetClient.send(exchangeData);
      });
    }
  }

  public listen() {
    this.server.on('upgrade', (request: http.IncomingMessage, socket: any, head: Buffer) => {
      this.wss.handleUpgrade(request, socket, head, (ws: ws.WebSocket) => {
        this.wss.emit('connection', ws, request);
      });
    });

    this.server.listen(this.port, () => {
      console.log(`App listening on the port ${this.port}`);
    });

    this.listenWebsocket();
  }
}

