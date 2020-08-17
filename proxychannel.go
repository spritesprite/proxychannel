package proxychannel

import (
	// "crypto/tls"
	"context"
	// "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	// "github.com/op/go-logging"
	// "github.com/vardius/shutdown"
	// messagebus "github.com/vardius/message-bus"
)

// Proxychannel is a prxoy that transfers data from http client
// to multiple dynamic proxies and get responses from them.
type Proxychannel struct {
	extensionManager *ExtensionManager
	server           *http.Server
	waitGroup        *sync.WaitGroup
	serverDone       chan bool
	// stopped          bool
	// stopping         bool
	// handler          *Proxy
	// conf             *Config
	// logger           Logger
}

// NewProxychannel creates a new Proxychannel
func NewProxychannel(hconf *HandlerConfig, sconf *ServerConfig, econf ExtensionManagerConfig) *Proxychannel {
	proxychannel := &Proxychannel{
		extensionManager: NewExtensionManager(econf),
		server:           NewServer(hconf, sconf),
		waitGroup:        &sync.WaitGroup{},
		serverDone:       make(chan bool),
		// stopped:          false,
		// stopping:         false,
	}
	return proxychannel
}

// NewServer returns an http.Server that defined by user config
func NewServer(hconf *HandlerConfig, sconf *ServerConfig) *http.Server {
	// handler := NewProxy(hconf)
	handler := NewProxy(WithoutDecryptHTTPS())
	server := &http.Server{
		Addr:         sconf.ProxyAddr,
		Handler:      handler,
		ReadTimeout:  sconf.ReadTimeout,
		WriteTimeout: sconf.WriteTimeout,
		TLSConfig:    sconf.TLSConfig,
	}
	return server
}

func (pc *Proxychannel) runExtensionManager() {
	defer pc.waitGroup.Done()
	go pc.extensionManager.Setup() // TODO: modify setup and error handling
	signalChan := make(chan os.Signal, 1)
	signal.Notify(
		signalChan,
		syscall.SIGHUP,  // kill -SIGHUP XXXX
		syscall.SIGINT,  // kill -SIGINT XXXX or Ctrl+c
		syscall.SIGTERM, // kill -SIGTERM XXXX
		syscall.SIGQUIT, // kill -SIGQUIT XXXX
	)

	// Will block until shutdown signal is received
	<-signalChan
	Logger.Info("os.Interrupt - shutting down...\n")

	// Will block until pc.server has been shut down
	<-pc.serverDone
	pc.extensionManager.Cleanup()
}

func (pc *Proxychannel) runServer() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(pc.serverDone)

	pc.server.BaseContext = func(_ net.Listener) context.Context { return ctx }

	stop := func() {
		gracefulCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := pc.server.Shutdown(gracefulCtx); err != nil {
			Logger.Errorf("shutdown error: %v\n", err)
		} else {
			Logger.Info("gracefully stopped\n")
		}
	}

	// Run server
	go func() {
		if err := pc.server.ListenAndServe(); err != http.ErrServerClosed {
			Logger.Errorf("HTTP server ListenAndServe: %v", err)
			os.Exit(1)
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(
		signalChan,
		syscall.SIGHUP,  // kill -SIGHUP XXXX
		syscall.SIGINT,  // kill -SIGINT XXXX or Ctrl+c
		syscall.SIGTERM, // kill -SIGTERM XXXX
		syscall.SIGQUIT, // kill -SIGQUIT XXXX
	)

	// Will block until shutdown signal is received
	<-signalChan
	Logger.Info("os.Interrupt - shutting down...\n")

	// Terminate after second signal before callback is done
	go func() {
		<-signalChan
		Logger.Error("os.Kill - terminating...\n")
		os.Exit(1)
	}()

	stop()
}

// Run launches the extensions and the proxy server
func (pc *Proxychannel) Run() {
	pc.waitGroup.Add(1)
	go pc.runExtensionManager()
	pc.runServer()
	pc.waitGroup.Wait()
}
