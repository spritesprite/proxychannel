package proxychannel

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/ouqiang/goproxy"
	"github.com/spritesprite/proxychannel/cert"
)

type NewExtensionFunction func(*ExtensionManager, ...interface{}) Extension

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

type LogConfig struct {
	LoggerName string
	LogLevel   string
	LogOut     string
	LogFormat  string
}

// Config proxychannel config
// type Config struct {
// 	extManagerConf ExtensionManagerConfig
// 	handlerConf    *HandlerConfig
// 	serverConf     *ServerConfig
// }
