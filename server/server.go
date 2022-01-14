package server

import (
	"crypto/sha256"
	"crypto/tls"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"github.com/xandout/soxy/proxy"
)

type soHandler struct {
	key      string
	upgrader websocket.Upgrader
}

// Start starts the http server
func Start(c *cli.Context) error {
	port := c.String("port")
	handler := &soHandler{
		key: c.String("key"),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}

	http.Handle("/", handler)
	err := http.ListenAndServe(port, nil)
	log.Errorf("HTTP SERVER: %v", err.Error())
	return err

}

func (h *soHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var useTLS bool
	if q.Get("useTLS") != "" {
		useTLS = true
	}
	ts := q.Get("ts")
	nts, _ := strconv.ParseInt(ts, 10, 64)
	diff := time.Now().UTC().Sub(time.Unix(nts, 0)).Seconds()
	if math.Abs(diff) > 30 {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("invalid ts"))
		log.Errorf("Error: invalid ts %v", ts)
		return
	}
	encRemote := q.Get("r")
	nonce := sha256.Sum256([]byte(ts))
	remote, err := proxy.Decrypt(encRemote, h.key, nonce[:])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("invalid remote"))
		return
	}

	if remote == "" {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("remote not set"))
		log.Errorf("HTTP SERVER: %v", "remote not set")
		return
	}
	wsConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		log.Errorf("HTTP SERVER, WS Connection Upgrade: %v", err.Error())
		return
	}
	var remoteTCPConn net.Conn
	if useTLS {
		remoteTCPConn, err = tls.Dial("tcp", remote, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		remoteTCPConn, err = net.Dial("tcp", remote)
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		log.Errorf("HTTP SERVER, TCP Write: %v", err.Error())
		return
	}
	log.Infof("Proxying traffic to %v on behalf of %v", remoteTCPConn.RemoteAddr(), wsConn.RemoteAddr())
	go proxy.Copy(wsConn, remoteTCPConn)
}
