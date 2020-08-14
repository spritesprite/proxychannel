package proxychannel

import (
	// "crypto/tls"
	"net/http"
	// "sync"
	"time"

	"github.com/ouqiang/goproxy"
)

// // Context the context shared by proxy server and extensions
// // TODO
// type Context struct {
// 	Req   *http.Request
// 	Data  map[interface{}]interface{}
// 	abort bool
// }

// Cache implements the Cache interface
type Cache struct {
	m sync.Map
}

// Set sets the cached cert of this host
func (c *Cache) Set(host string, cert *tls.Certificate) {
	c.m.Store(host, cert)
}

// Get gets the cached cert of this host
func (c *Cache) Get(host string) *tls.Certificate {
	v, ok := c.m.Load(host)
	if !ok {
		return nil
	}
	return v.(*tls.Certificate)
}

// Proxychannel is a prxoy that transfers data from http client
// to multiple dynamic proxies and get responses from them.
type Proxychannel struct {
	extensionManager *ExtensionManager
	delegate         *goproxy.Delegate
	stopped          bool
	stopping         bool
	// logger           Logger
}

// NewProxychannel creates a new Proxychannel
func NewProxychannel() *Proxychannel {
	proxychannel := &Proxychannel{
		extensionManager: NewExtensionManager(),
		delegate:         &DefaultDelegate{},
		stopped:          false,
		stopping:         false,
	}
	return proxychannel
}

func (pc *Proxychannel) Run(serverConf *ServerConfig, handlerConf *HandlerConfig) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		extensionManager
		extensionManager.LoadExtensions(xxxconf) // TODO
		extensionManager.Setup()
	}()

	go func() {
		defer wg.Done()
		handler := goproxy.New(handlerConf)
		server := &http.Server{
			Addr:         serverConf.ProxyAddr,
			Handler:      handler,
			ReadTimeout:  serverConf.ReadTimeout,
			WriteTimeout: serverConf.WriteTimeout,
			TLSConfig:    serverConf.TLSConfig,
		}
		err := server.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	wg.Wait()
}
