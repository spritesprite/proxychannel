package proxychannel

import (
	"net/http"

	"github.com/ouqiang/goproxy"
	"github.com/spritesprite/goproxy/cert"
)

type NewExtensionFunction func(*ExtensionManager, ...interface{}) *Extension

type ExtensionConfig struct {
	ExtNewFunc NewExtensionFunction
	Params     []interface{}
}

// ExtensionManagerConfig is the config of ext manager
type ExtensionManagerConfig map[string]*ExtensionConfig

type HandlerConfig struct {
	disableKeepAlive bool
	delegate         goproxy.Delegate
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

// Config proxychannel config
type Config struct {
	extConf     ExtensionConfig
	handlerConf HandlerConfig
	serverConf  ServerConfig
}
