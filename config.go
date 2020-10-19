package proxychannel

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/spritesprite/proxychannel/cert"
)

// Cache is a concurrent map.
type Cache struct {
	m sync.Map
}

// Set stores the certificates of hosts that have been seen.
func (c *Cache) Set(host string, cert *tls.Certificate) {
	c.m.Store(host, cert)
}

// Get gets the certificate stored.
func (c *Cache) Get(host string) *tls.Certificate {
	v, ok := c.m.Load(host)
	if !ok {
		return nil
	}

	return v.(*tls.Certificate)
}

// DefaultHandlerConfig .
var DefaultHandlerConfig *HandlerConfig = &HandlerConfig{
	DisableKeepAlive: false,
	Delegate:         &DefaultDelegate{},
	DecryptHTTPS:     false,
	CertCache:        &Cache{},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			// Timeout:   30 * time.Second,
			// KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// DefaultServerConfig .
var DefaultServerConfig *ServerConfig = &ServerConfig{
	ProxyAddr: ":8008",
	// ReadTimeout: 60 * time.Second,
	// WriteTimeout: 60 * time.Second,
}

// HandlerConfig .
type HandlerConfig struct {
	DisableKeepAlive bool
	Delegate         Delegate
	DecryptHTTPS     bool
	CertCache        cert.Cache
	Transport        *http.Transport
}

// ServerConfig .
type ServerConfig struct {
	ProxyAddr    string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	TLSConfig    *tls.Config
}

// LogConfig .
type LogConfig struct {
	LoggerName string
	LogLevel   string
	LogOut     string
	LogFormat  string
}
