package proxychannel

import (
	// "crypto/tls"
	"net/http"
	// "sync"
	"time"

	"github.com/ouqiang/goproxy"
)

type Proxychannel struct {
	extensionManager *ExtensionManager
	delegate         *goproxy.Delegate
	stopped          bool
	stopping         bool
	logger           Logger
}

func NewProxychannel() *Proxychannel {
	proxychannel := &Proxychannel{}
	proxychannel.extensionManager = ExtensionManager
	return proxychannel
}

func (*Proxychannel) Run() {
	proxy := goproxy.New(goproxy.WithDecryptHTTPS(&Cache{}))
	// proxy := goproxy.New(goproxy.WithoutDecryptHTTPS())
	// nextProtos := []string{"h2", "http/1.1"}
	// tlsConfig := &tls.Config{NextProtos: nextProtos}
	server := &http.Server{
		Addr:         ":8001",
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
		// TLSConfig:    tlsConfig,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
