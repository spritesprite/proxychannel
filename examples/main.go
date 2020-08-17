package main

import (
	"github.com/spritesprite/proxychannel"
)

func main() {
	// ConfigLogging(proxychannel.DefaultLogConfig)
	pc := proxychannel.NewProxychannel(
		proxychannel.DefaultHandlerConfig,
		proxychannel.DefaultServerConfig,
		proxychannel.DefaultExtensionManagerConfig)
	pc.Run()
}
