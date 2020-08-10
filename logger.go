package proxychannel

type Logger interface {
	Printf(format string, v ...interface{})
}
