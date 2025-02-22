package peerprotocol

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/chik-network/go-chik-libs/pkg/types"

	"github.com/gorilla/websocket"

	"github.com/chik-network/go-chik-libs/pkg/config"
	"github.com/chik-network/go-chik-libs/pkg/protocols"
)

// Connection represents a connection with a peer and enables communication
type Connection struct {
	chikConfig *config.ChikConfig

	networkID   string
	peerIP      *net.IP
	peerPort    uint16
	peerKeyPair *tls.Certificate
	peerDialer  *websocket.Dialer
	peerID      types.Bytes32

	handshakeTimeout time.Duration
	conn             *websocket.Conn
}

// PeerResponseHandlerFunc is a function that will be called when a response is returned from a peer
type PeerResponseHandlerFunc func(*protocols.Message, error)

// NewConnection creates a new connection object with the specified peer
func NewConnection(ip *net.IP, options ...ConnectionOptionFunc) (*Connection, error) {
	c := &Connection{
		peerIP: ip,
	}

	for _, fn := range options {
		if fn == nil {
			continue
		}
		if err := fn(c); err != nil {
			return nil, err
		}
	}

	if c.peerPort == 0 {
		if err := c.loadChikConfig(); err != nil {
			return nil, err
		}
		c.peerPort = c.chikConfig.FullNode.Port
	}

	if c.peerKeyPair == nil {
		if err := c.loadChikConfig(); err != nil {
			return nil, err
		}
		if err := c.loadConfigKeyPair(); err != nil {
			return nil, err
		}
	}

	if len(c.networkID) == 0 {
		if err := c.loadChikConfig(); err != nil {
			return nil, err
		}
		if c.chikConfig.SelectedNetwork == nil {
			return nil, errors.New("selected_network empty in config")
		}
		c.networkID = *c.chikConfig.SelectedNetwork
	}

	// Generate the websocket dialer
	if err := c.generateDialer(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Connection) loadChikConfig() error {
	if c.chikConfig != nil {
		return nil
	}
	cfg, err := config.GetChikConfig()
	if err != nil {
		return err
	}
	c.chikConfig = cfg
	return nil
}

func (c *Connection) loadConfigKeyPair() error {
	var err error

	c.peerKeyPair, err = c.chikConfig.FullNode.SSL.LoadPublicKeyPair(c.chikConfig.ChikRoot)
	if err != nil {
		return err
	}

	return nil
}

func (c *Connection) generateDialer() error {
	if c.peerDialer == nil {
		c.peerDialer = &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: c.handshakeTimeout,
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*c.peerKeyPair},
				InsecureSkipVerify: true,
			},
		}
	}

	return nil
}

// ensureConnection ensures there is an open websocket connection
func (c *Connection) ensureConnection() error {
	if c.conn == nil {
		host := fmt.Sprintf("%s:%d", c.peerIP.String(), c.peerPort)
		if c.peerIP.To4() == nil {
			host = fmt.Sprintf("[%s]:%d", c.peerIP.String(), c.peerPort)
		}
		u := url.URL{Scheme: "wss", Host: host, Path: "/ws"}
		var err error
		c.conn, _, err = c.peerDialer.Dial(u.String(), nil)
		if err != nil {
			return err
		}

		tlsConn, ok := c.conn.NetConn().(*tls.Conn)
		if !ok {
			return fmt.Errorf("could not get tls.Conn from websocket")
		}

		// Access the connection state
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("no certificates in chain")
		}

		c.peerID = sha256.Sum256(state.PeerCertificates[0].Raw)
	}

	return nil
}

// Close closes the connection, if open
func (c *Connection) Close() {
	if c.conn != nil {
		err := c.conn.Close()
		if err != nil {
			return
		}
		c.conn = nil
	}
}

// PeerID returns the Peer ID for the remote peer
func (c *Connection) PeerID() (types.Bytes32, error) {
	err := c.ensureConnection()
	if err != nil {
		return types.Bytes32{}, err
	}

	return c.peerID, nil
}

// Handshake performs the RPC handshake. This should be called before any other method
func (c *Connection) Handshake() error {
	// Handshake
	handshake := &protocols.Handshake{
		NetworkID:       c.networkID,
		ProtocolVersion: protocols.ProtocolVersion,
		SoftwareVersion: "2.0.0",
		ServerPort:      c.peerPort,
		NodeType:        protocols.NodeTypeFullNode, // I guess we're a full node
		Capabilities: []protocols.Capability{
			{
				Capability: protocols.CapabilityTypeBase,
				Value:      "1",
			},
		},
	}

	return c.Do(protocols.ProtocolMessageTypeHandshake, handshake)
}

// Do send a request over the websocket
func (c *Connection) Do(messageType protocols.ProtocolMessageType, data interface{}) error {
	err := c.ensureConnection()
	if err != nil {
		return err
	}

	msgBytes, err := protocols.MakeMessageBytes(messageType, data)
	if err != nil {
		return err
	}

	return c.conn.WriteMessage(websocket.BinaryMessage, msgBytes)
}

// ReadSync Reads for async responses over the connection in a synchronous fashion, blocking anything else
func (c *Connection) ReadSync(handler PeerResponseHandlerFunc) error {
	for {
		_, bytes, err := c.conn.ReadMessage()
		if err != nil {
			// @TODO Handle Error
			return err

		}
		handler(protocols.DecodeMessage(bytes))
	}
}

// ReadOne reads and returns one message from the connection
func (c *Connection) ReadOne(timeout time.Duration) (*protocols.Message, error) {
	chBytes := make(chan []byte, 1)
	chErr := make(chan error, 1)
	ctxTimeout, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go c.readOneCtx(ctxTimeout, chBytes, chErr)

	select {
	case <-ctxTimeout.Done():
		return nil, fmt.Errorf("context cancelled: %v", ctxTimeout.Err())
	case result := <-chBytes:
		return protocols.DecodeMessage(result)
	}
}

func (c *Connection) readOneCtx(ctx context.Context, chBytes chan []byte, chErr chan error) {
	_, bytes, err := c.conn.ReadMessage()
	if err != nil {
		chErr <- err
	}

	chBytes <- bytes
}
