package main

import (
	"github.com/spritesprite/proxychannel"
)

func main() {
	// Providing certain log configuration before Run() is optional
	// e.g. ConfigLogging(lconf) where lconf is a *LogConfig
	pc := proxychannel.NewProxychannel(
		proxychannel.DefaultHandlerConfig,
		proxychannel.DefaultServerConfig,
		make(map[string]proxychannel.Extension))
	pc.Run()
}
