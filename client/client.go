package client

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"github.com/xandout/soxy/proxy"
)

// Start starts a soxy client
func Start(c *cli.Context) error {
	l, err := net.Listen("tcp", c.String("local"))
	if err != nil {
		log.Errorf("TCP LISTENER: %v", err.Error())
		os.Exit(1)
	}

	// Close the listener when the application closes.
	defer l.Close()

	log.Info("Listening on " + c.String("local"))
	key := c.String("key")
	for {
		// Listen for an incoming connection.
		tcpConn, err := l.Accept()
		if err != nil {
			log.Errorf("TCP ACCEPT: %v", err.Error())
		}

		fmtString := "%s/?ts=%s&r=%s"
		ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		nonce := sha256.Sum256([]byte(ts))
		encRemote, err := proxy.Encrypt(c.String("remote"), key, nonce[:])
		if err != nil {
			log.Errorf("DIALER: key error: %v", err.Error())
			return err
		}
		fmted := fmt.Sprintf(fmtString, c.String("soxy-url"), ts, encRemote)
		clientWsConn, _, err := websocket.DefaultDialer.Dial(fmted, nil)
		if err != nil {
			log.Errorf("DIALER: %v", err.Error())
			return err
		}
		// Handle connections in a new goroutine.
		log.Infof("Proxying traffic to %v via %v for %v", c.String("remote"), clientWsConn.RemoteAddr(), tcpConn.RemoteAddr())
		go proxy.Copy(clientWsConn, tcpConn)
	}
}
