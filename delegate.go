package proxychannel

import (
	// "crypto/tls"
	"net/http"
	"net/url"
)

// ResponseWrapper is simply a wrapper for http.Response and error.
type ResponseWrapper struct {
	Resp *http.Response
	Err  error
}

// Context stores what methods of Delegate would need as input.
type Context struct {
	Req        *http.Request
	Data       map[interface{}]interface{}
	abort      bool
	Hijack     bool
	MITM       bool
	ReqLength  int64
	RespLength int64
	ErrType    string
	Err        error
}

// Abort sets abort to true.
func (c *Context) Abort() {
	c.abort = true
}

// AbortWithError sets Err and abort to true.
func (c *Context) AbortWithError(err error) {
	c.Err = err
	c.abort = true
}

// IsAborted checks whether abort is set to true.
func (c *Context) IsAborted() bool {
	return c.abort
}

// Delegate defines some extra manipulation on requests set by user.
type Delegate interface {
	GetExtensionManager() *ExtensionManager
	SetExtensionManager(*ExtensionManager)
	Connect(ctx *Context, rw http.ResponseWriter)
	Auth(ctx *Context, rw http.ResponseWriter)
	BeforeRequest(ctx *Context)
	BeforeResponse(ctx *Context, resp *ResponseWrapper)
	ParentProxy(ctx *Context, i interface{}) (*url.URL, error)
	DuringResponse(ctx *Context, i interface{})
	Finish(ctx *Context, rw http.ResponseWriter)
}

var _ Delegate = &DefaultDelegate{}

// DefaultDelegate basically does nothing.
type DefaultDelegate struct {
	Delegate
}

// GetExtensionManager .
func (h *DefaultDelegate) GetExtensionManager() *ExtensionManager {
	return nil
}

// SetExtensionManager .
func (h *DefaultDelegate) SetExtensionManager(em *ExtensionManager) {}

// Connect .
func (h *DefaultDelegate) Connect(ctx *Context, rw http.ResponseWriter) {}

// Auth .
func (h *DefaultDelegate) Auth(ctx *Context, rw http.ResponseWriter) {}

// BeforeRequest .
func (h *DefaultDelegate) BeforeRequest(ctx *Context) {}

// BeforeResponse .
func (h *DefaultDelegate) BeforeResponse(ctx *Context, resp *ResponseWrapper) {}

// ParentProxy .
func (h *DefaultDelegate) ParentProxy(ctx *Context, i interface{}) (*url.URL, error) {
	return http.ProxyFromEnvironment(ctx.Req)
}

// DuringResponse .
func (h *DefaultDelegate) DuringResponse(ctx *Context, i interface{}) {}

// Finish .
func (h *DefaultDelegate) Finish(ctx *Context, rw http.ResponseWriter) {}
