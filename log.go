package proxychannel

import (
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/op/go-logging"
)

var rootLoggerName string = "ProxyChannel"

// Logger is used to print log in proxychannel
var Logger *logging.Logger = logging.MustGetLogger(rootLoggerName)

// Default Settings
const (
	DefaultLoggerName    = "ProxyChannel"
	DefaultLogTimeFormat = "2006-01-02 15:04:05"
	DefaultLogLevel      = "debug"
	DefaultLogOut        = "stderr"
	DefaultLogFormat     = `[%{time:` + DefaultLogTimeFormat + `}] [%{module}] [%{level}] %{message}`
)

func init() {
	var out io.Writer

	switch DefaultLogOut {
	case "stderr":
		out = os.Stderr
	case "stdout":
		out = os.Stdout
	default:
		out = ioutil.Discard
	}

	backend := logging.NewLogBackend(out, "", 0)
	logging.SetBackend(backend)

	l := logging.GetLevel(DefaultLogLevel)
	logging.SetLevel(l, DefaultLoggerName)

	formatter := logging.MustStringFormatter(DefaultLogFormat)
	logging.SetFormatter(formatter)
}

func ConfigLogging(conf *LogConfig) error {
	if err := SetLoggingBackend(conf.LogOut); err != nil {
		return err
	}
	if err := SetLoggingFormat(conf.LogFormat); err != nil {
		return err
	}
	debug := false
	if conf.LogLevel == "debug" {
		debug = true
	}
	if err := SetLoggingLevel(conf.LogLevel, debug); err != nil {
		return err
	}

	return nil
}

// SetLoggingLevel TODO
func SetLoggingLevel(level string, debug bool) error {

	if strings.TrimSpace(level) == "" {
		level = DefaultLogLevel
	}
	var logLevel logging.Level
	var err error
	if logLevel, err = logging.LogLevel(level); err != nil {
		return err
	}

	if debug {
		logLevel = logging.DEBUG
	}
	logging.SetLevel(logLevel, DefaultLoggerName)
	return nil
}

// SetLoggingFormat TODO
func SetLoggingFormat(format string) error {
	var formatter logging.Formatter
	var err error
	if formatter, err = logging.NewStringFormatter(format); err != nil {
		return err
	}
	logging.SetFormatter(formatter)
	return nil
}

// SetLoggingBackend TODO
func SetLoggingBackend(out string) error {
	var o io.Writer
	switch out {
	case "stdout":
		o = os.Stdout
	case "stderr", "":
		o = os.Stderr
	default:
		f, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)

		if err != nil {
			return err
		}

		o = f
	}

	backend := logging.NewLogBackend(o, "", 0)
	logging.SetBackend(backend)
	return nil
}
