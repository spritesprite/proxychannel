module github.com/elazarl/goproxy/examples/goproxy-transparent

require (
	github.com/ecordell/goproxy v0.0.0-20160321142815-68c684f60e7a
	github.com/elazarl/goproxy v0.0.0-20181111060418-2ce16c963a8a
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2
	github.com/gorilla/websocket v1.4.2
	github.com/inconshreveable/go-vhost v0.0.0-20160627193104-06d84117953b
)

replace github.com/elazarl/goproxy => ../

go 1.13
