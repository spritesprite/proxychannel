package proxychannel

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/spritesprite/proxychannel/cert"
)

type Cache struct {
	m sync.Map
}

func (c *Cache) Set(host string, cert *tls.Certificate) {
	c.m.Store(host, cert)
}
func (c *Cache) Get(host string) *tls.Certificate {
	v, ok := c.m.Load(host)
	if !ok {
		return nil
	}

	return v.(*tls.Certificate)
}

var DefaultHandlerConfig *HandlerConfig = &HandlerConfig{
	disableKeepAlive: false,
	delegate:         &DefaultDelegate{},
	decryptHTTPS:     false,
	certCache:        &Cache{},
	transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

var DefaultServerConfig *ServerConfig = &ServerConfig{
	ProxyAddr:    ":8008",
	ReadTimeout:  60 * time.Second,
	WriteTimeout: 60 * time.Second,
}

type HandlerConfig struct {
	disableKeepAlive bool
	delegate         Delegate
	decryptHTTPS     bool
	certCache        cert.Cache
	transport        *http.Transport
}

type ServerConfig struct {
	ProxyAddr    string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	TLSConfig    *tls.Config
}

type LogConfig struct {
	LoggerName string
	LogLevel   string
	LogOut     string
	LogFormat  string
}
