package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

var addr = flag.String("addr", "localhost:8080", "http service address")

var c *websocket.Conn

func main() {
	flag.Parse()
	log.SetFlags(0)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/ws"}
	log.Printf("connecting to %s", u.String())

	var err error
	c, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	done := make(chan struct{})

	var hehe string
	fmt.Println("initiator? [Y/N]")
	fmt.Scanln(&hehe)

	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				return
			}
			log.Printf("recv: %s", message)

			var data map[string]interface{}
			_ = json.Unmarshal(message, &data)

			switch data["kind"] {
			case "nonce":
				var nickname string
				fmt.Println("Enter nickname:")
				fmt.Scanln(&nickname)
				Register(nickname, data["value"].(string))
			case "notification":
				switch data["replyTo"] {
				case "registration":
					if hehe == "Y" {
						var targetPublicKey string
						fmt.Println("Enter target:")
						fmt.Scanln(&targetPublicKey)
						PrepareForKeyExchange()
						PerformKeyExchange(targetPublicKey)
					}
				}
			case "keyExchange":
				HandleKeyExchange(data["info"].(map[string]interface{}))
			case "e2eeMessage":
				log.Println("decrypted", Decrypt(data))
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("interrupt")

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

