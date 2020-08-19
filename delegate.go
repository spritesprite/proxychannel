package proxychannel

import (
	"log"
	"net/http"
	"net/url"
)

// Context 代理上下文
type Context struct {
	Req   *http.Request
	Data  map[interface{}]interface{}
	abort bool
}

// Abort 中断执行
func (c *Context) Abort() {
	c.abort = true
}

// IsAborted 是否已中断执行
func (c *Context) IsAborted() bool {
	return c.abort
}

type Delegate interface {
	GetExtensionManager() *ExtensionManager
	SetExtensionManager(*ExtensionManager)
	Connect(ctx *Context, rw http.ResponseWriter)
	Auth(ctx *Context, rw http.ResponseWriter)
	BeforeRequest(ctx *Context)
	BeforeResponse(ctx *Context, resp *http.Response, err error)
	ParentProxy(*http.Request) (*url.URL, error)
	Finish(ctx *Context)
}

var _ Delegate = &DefaultDelegate{}

// DefaultDelegate 默认Handler什么也不做
type DefaultDelegate struct {
	Delegate
}

func (h *DefaultDelegate) Connect(ctx *Context, rw http.ResponseWriter) {}

func (h *DefaultDelegate) Auth(ctx *Context, rw http.ResponseWriter) {}

func (h *DefaultDelegate) BeforeRequest(ctx *Context) {}

func (h *DefaultDelegate) BeforeResponse(ctx *Context, resp *http.Response, err error) {}

func (h *DefaultDelegate) ParentProxy(req *http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment(req)
}

func (h *DefaultDelegate) Finish(ctx *Context) {}

func (h *DefaultDelegate) ErrorLog(err error) {
	log.Println(err)
}
