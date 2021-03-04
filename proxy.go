package proxychannel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jmcvetta/randutil"
	"github.com/spritesprite/proxychannel/cert"
)

// Default timeout values
const (
	defaultTargetConnectTimeout   = 5 * time.Second
	defaultTargetReadWriteTimeout = 30 * time.Second
	defaultClientReadWriteTimeout = 30 * time.Second
)

const defaultHTTPResponsePeekSize int = 4096

// Canned HTTP responses
var tunnelEstablishedResponseLine = []byte(fmt.Sprintf("HTTP/1.1 %d Connection established\r\n\r\n", http.StatusOK))
var badGateway = fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", http.StatusBadGateway, http.StatusText(http.StatusBadGateway))
var tooManyRequests = fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests))

var internalErr = "PROXY_CHANNEL_INTERNAL_ERR"

// ProxyError specifies all the possible errors that can occur due to this proxy's behavior,
// which does not include the behavior of parent proxies.
type ProxyError struct {
	ErrType string `json:"errType"`
	ErrCode int32  `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
}

// TunnelConn .
type TunnelConn struct {
	Client net.Conn
	Target net.Conn
}

// TunnelInfo .
type TunnelInfo struct {
	Client      net.Conn
	Target      net.Conn
	Err         error
	ParentProxy *url.URL
	Pool        ConnPool
}

// ResponseInfo .
type ResponseInfo struct {
	Resp        *http.Response
	Err         error
	ParentProxy *url.URL
	Pool        ConnPool
}

// ResponseWrapper is simply a wrapper for http.Response and error.
type ResponseWrapper struct {
	Resp *http.Response
	Err  error
}

// ConnWrapper .
type ConnWrapper struct {
	Conn net.Conn
	Err  error
}

// Below are the modes supported.
const (
	NormalMode = iota
	ConnPoolMode
)

func makeTunnelRequestLine(addr string) string {
	return fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", addr)
}

func makeTunnelRequestWithAuth(ctx *Context, parentProxyURL *url.URL, targetConn net.Conn) error {
	connectReq := &http.Request{
		Proto:      ctx.Req.Proto,
		ProtoMajor: ctx.Req.ProtoMajor,
		ProtoMinor: ctx.Req.ProtoMinor,
		Method:     "CONNECT",
		URL:        &url.URL{Opaque: ctx.Req.URL.Host},
		Host:       ctx.Req.URL.Host,
		Header:     CloneHeader(ctx.Req.Header),
	}
	if connectReq.Proto == "HTTP/1.0" {
		connectReq.Header.Del("Connection")
	}
	u := parentProxyURL.User
	if u != nil {
		username := u.Username()
		password, _ := u.Password()
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		connectReq.Header.Set("Proxy-Authorization", basicAuth)
	}
	return connectReq.Write(targetConn)
}

// Proxy is a struct that implements ServeHTTP() method
type Proxy struct {
	delegate      Delegate
	clientConnNum int32
	decryptHTTPS  bool
	cert          *cert.Certificate
	transport     *http.Transport
	mode          int
}

var _ http.Handler = &Proxy{}

// NewProxy creates a Proxy instance (an HTTP handler)
func NewProxy(hconf *HandlerConfig, em *ExtensionManager) *Proxy {
	p := &Proxy{}

	if hconf.Delegate == nil {
		p.delegate = &DefaultDelegate{}
	} else {
		p.delegate = hconf.Delegate
	}
	p.delegate.SetExtensionManager(em)

	p.cert = cert.NewCertificate(hconf.CertCache)

	if hconf.Transport == nil {
		p.transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				// No need to verify because as a proxy we don't care
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ProxyConnectHeader:    make(http.Header),
		}
	} else {
		p.transport = hconf.Transport
		p.transport.ProxyConnectHeader = make(http.Header)
	}
	p.transport.DisableKeepAlives = hconf.DisableKeepAlive
	p.mode = hconf.Mode
	if p.mode == ConnPoolMode {
		p.transport.ProxyConnectHeader.Set("MITM", "Enabled")
	}
	return p
}

// ServeHTTP .
func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	atomic.AddInt32(&p.clientConnNum, 1)
	defer func() {
		atomic.AddInt32(&p.clientConnNum, -1)
	}()
	ctx := &Context{
		Req:        req,
		Data:       make(map[interface{}]interface{}),
		Hijack:     false,
		MITM:       false,
		ReqLength:  0,
		RespLength: 0,
		Closed:     false,
	}
	defer p.delegate.Finish(ctx, rw)
	p.delegate.Connect(ctx, rw)
	if ctx.abort {
		ctx.SetContextErrType(ConnectFail)
		return
	}
	p.delegate.Auth(ctx, rw)
	if ctx.abort {
		ctx.SetContextErrType(AuthFail)
		return
	}

	// NormalMode:
	// This proxy will forward requests to parent proxy, and return whatever it gets
	// from parent proxy back to requestor.

	// ConnPoolMode:
	// This proxy chooses a TCP connection by given probability from the ConnPool,
	// which is specified by p.delegate.GetConnPool(ctx).
	// If this proxy fails to connect parent proxy or gets a response body in JSON
	// format that has an "ErrType" of "PROXY_CHANNEL_INTERNAL_ERR"(especially when
	// the parent proxy is also a proxychannel instance), it retries the proxy request
	// with another proxy chosen from ConnPool by given probability.
	// The retry goes on until any parent proxy returns a 200 response code or every
	// connection has been chosen.
	switch p.mode {
	case NormalMode:
		if ctx.Req.Method == http.MethodConnect {
			h := ctx.Req.Header.Get("MITM")
			if h == "Enabled" {
				ctx.MITM = true
				if isWebSocketRequest(ctx.Req) {
					p.proxyHTTPSWebsocket(ctx, rw)
				} else {
					p.proxyHTTPS(ctx, rw)
				}
			} else {
				p.proxyTunnel(ctx, rw)
			}
		} else {
			if isWebSocketRequest(ctx.Req) {
				p.proxyHTTPWebsocket(ctx, rw)
			} else {
				p.proxyHTTP(ctx, rw)
			}
		}
	case ConnPoolMode:
		if ctx.Req.Method == http.MethodConnect {
			p.proxyTunnelWithConnPool(ctx, rw)
		} else {
			p.proxyHTTPWithConnPool(ctx, rw)
		}
	}
}

// ClientConnNum gets the Client
func (p *Proxy) ClientConnNum() int32 {
	return atomic.LoadInt32(&p.clientConnNum)
}

// WriteProxyErrorToResponseBody is the standard function to call when errors occur due to this proxy's behavior,
// which does not include the behavior of parent proxies.
func WriteProxyErrorToResponseBody(ctx *Context, respWriter Writer, httpcode int32, msg string, optionalPrefix string) {
	if optionalPrefix != "" {
		m, _ := respWriter.Write([]byte(optionalPrefix))
		ctx.RespLength += int64(m)
	}
	pe := &ProxyError{
		ErrType: internalErr,
		ErrCode: httpcode,
		ErrMsg:  msg,
	}
	errJSON, err := json.Marshal(pe)
	if err != nil {
		panic(fmt.Errorf("jason marshal failed"))
	}
	n, _ := respWriter.Write(errJSON)
	ctx.RespLength += int64(n)
}

func (p *Proxy) proxyHTTP(ctx *Context, rw http.ResponseWriter) {
	ctx.Req.URL.Scheme = "http"
	p.DoRequest(ctx, rw, func(resp *http.Response, err error) {
		if err != nil {
			Logger.Errorf("proxyHTTP %s forward request failed: %s", ctx.Req.URL, err)
			rw.WriteHeader(http.StatusBadGateway)
			WriteProxyErrorToResponseBody(ctx, rw, http.StatusBadGateway, fmt.Sprintf("proxyHTTP %s forward request failed: %s", ctx.Req.URL, err), "")
			ctx.SetContextErrorWithType(err, HTTPDoRequestFail)
			return
		}

		defer resp.Body.Close()
		p.delegate.DuringResponse(ctx, resp)

		CopyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)

		written, err := io.Copy(rw, resp.Body)
		ctx.RespLength += written
		if err != nil {
			Logger.Errorf("proxyHTTP %s write client failed: %s", ctx.Req.URL, err)
			ctx.SetContextErrorWithType(err, HTTPWriteClientFail)
			return
		}
	})
}

func (p *Proxy) proxyHTTPS(ctx *Context, rw http.ResponseWriter) {
	tlsConfig, err := p.cert.GenerateTLSConfig(ctx.Req.URL.Host)
	if err != nil {
		Logger.Errorf("proxyHTTPS %s generate tlsConfig failed: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		WriteProxyErrorToResponseBody(ctx, rw, http.StatusBadGateway, fmt.Sprintf("proxyHTTPS %s generate tlsConfig failed: %s", ctx.Req.URL, err), "")
		ctx.SetContextErrorWithType(err, HTTPSGenerateTLSConfigFail)
		return
	}
	clientConn, err := hijacker(rw)
	if err != nil {
		Logger.Errorf("proxyHTTPS hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		WriteProxyErrorToResponseBody(ctx, rw, http.StatusBadGateway, fmt.Sprintf("proxyHTTPS hijack client connection failed: %s", err), "")
		ctx.SetContextErrorWithType(err, HTTPSHijackClientConnFail)
		return
	}
	ctx.Hijack = true
	defer clientConn.Close()
	_, err = clientConn.Write(tunnelEstablishedResponseLine)
	if err != nil {
		Logger.Errorf("proxyHTTPS %s write message failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSWriteEstRespFail)
		return
	}
	// tlsConfig.NextProtos = []string{"h2", "http/1.1", "http/1.0"}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	// tlsClientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	defer tlsClientConn.Close()
	if err := tlsClientConn.Handshake(); err != nil {
		Logger.Errorf("proxyHTTPS %s handshake failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSTLSClientConnHandshakeFail)
		return
	}
	buf := bufio.NewReader(tlsClientConn)
	tlsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			Logger.Errorf("proxyHTTPS %s read client request failed: %s", ctx.Req.URL.Host, err)
			ctx.SetContextErrorWithType(err, HTTPSReadReqFromBufFail)
		}
		return
	}
	tlsReq.RemoteAddr = ctx.Req.RemoteAddr
	tlsReq.URL.Scheme = "https"
	tlsReq.URL.Host = tlsReq.Host

	ctx.Req = tlsReq
	p.DoRequest(ctx, rw, func(resp *http.Response, err error) {
		if err != nil {
			Logger.Errorf("proxyHTTPS %s forward request failed: %s", ctx.Req.URL.Host, err)
			WriteProxyErrorToResponseBody(ctx, tlsClientConn, http.StatusBadGateway, fmt.Sprintf("proxyHTTPS %s forward request failed: %s", ctx.Req.URL.Host, err), badGateway)
			ctx.SetContextErrorWithType(err, HTTPSDoRequestFail)
			return
		}
		defer resp.Body.Close()
		p.delegate.DuringResponse(ctx, resp) // resp could be closed in this method

		lengthWriter := &WriterWithLength{tlsClientConn, 1, 0}
		err = resp.Write(lengthWriter)
		if err != nil {
			Logger.Errorf("proxyHTTPS %s write response to client connection failed: %s", ctx.Req.URL.Host, err)
			ctx.SetContextErrorWithType(err, HTTPSWriteRespFail)
		}
		ctx.RespLength += int64(lengthWriter.Length())
	}, tlsClientConn)
}

func (p *Proxy) proxyTunnel(ctx *Context, rw http.ResponseWriter) {
	parentProxyURL, err := p.delegate.ParentProxy(ctx, rw)
	if ctx.abort {
		ctx.SetContextErrType(ParentProxyFail)
		return
	}
	clientConn, err := hijacker(rw)
	if err != nil {
		Logger.Errorf("proxyTunnel hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		WriteProxyErrorToResponseBody(ctx, rw, http.StatusBadGateway, fmt.Sprintf("proxyTunnel hijack client connection failed: %s", err), "")
		ctx.SetContextErrorWithType(err, TunnelHijackClientConnFail)
		return
	}
	ctx.Hijack = true
	defer func() {
		err := clientConn.Close()
		if err != nil {
			Logger.Infof("defer client close err: %s", err)
		} else {
			Logger.Infof("defer client close done")
		}
	}()
	// defer clientConn.Close()

	targetAddr := ctx.Req.URL.Host
	if parentProxyURL != nil {
		targetAddr = parentProxyURL.Host
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)

	connWrapper := &ConnWrapper{
		Conn: targetConn,
		Err:  err,
	}
	p.delegate.BeforeResponse(ctx, connWrapper)
	if ctx.abort {
		ctx.SetContextErrType(BeforeResponseFail)
		return
	}
	if err != nil {
		Logger.Errorf("proxyTunnel %s dial remote server failed: %s", ctx.Req.URL.Host, err)
		WriteProxyErrorToResponseBody(ctx, clientConn, http.StatusBadGateway, fmt.Sprintf("proxyTunnel %s dial remote server failed: %s", ctx.Req.URL.Host, err), badGateway)
		ctx.SetContextErrorWithType(err, TunnelDialRemoteServerFail)
		return
	}
	// defer targetConn.Close()
	defer func() {
		err := targetConn.Close()
		if err != nil {
			Logger.Infof("defer target close err: %s", err)
		} else {
			Logger.Infof("defer target close done")
		}
	}()
	p.delegate.DuringResponse(ctx, &TunnelConn{Client: clientConn, Target: targetConn}) // targetConn could be closed in this method
	if parentProxyURL == nil {
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			Logger.Errorf("proxyTunnel %s write message failed: %s", ctx.Req.URL.Host, err)
			ctx.SetContextErrorWithType(err, TunnelWriteEstRespFail)
			return
		}
	} else {
		err := makeTunnelRequestWithAuth(ctx, parentProxyURL, targetConn)
		if err != nil {
			Logger.Errorf("proxyTunnel %s make connect request to remote failed: %s", ctx.Req.URL.Host, err)
			WriteProxyErrorToResponseBody(ctx, clientConn, http.StatusBadGateway, fmt.Sprintf("proxyTunnel %s make connect request to remote failed: %s", ctx.Req.URL.Host, err), badGateway)
			ctx.SetContextErrorWithType(err, TunnelConnectRemoteFail)
			return
		}
	}
	transfer(ctx, clientConn, targetConn)
}

// transfer does two-way forwarding through connections
func transfer(ctx *Context, clientConn net.Conn, targetConn net.Conn, parentProxy ...string) {
	go func() {
		written1, err1 := io.Copy(clientConn, targetConn)
		if err1 != nil {
			Logger.Errorf("io.Copy write clientConn failed: %s", err1)
			if len(parentProxy) <= 1 {
				if len(parentProxy) == 0 {
					ctx.SetContextErrorWithType(err1, TunnelWriteClientConnFinish)
				} else {
					ctx.SetPoolContextErrorWithType(err1, TunnelWriteClientConnFinish, parentProxy[0])
				}
			}
		}
		ctx.RespLength += written1
		clientConn.Close()
		targetConn.Close()
	}()
	written2, err2 := io.Copy(targetConn, clientConn)
	if err2 != nil {
		Logger.Errorf("io.Copy write targetConn failed: %s", err2)
		if len(parentProxy) <= 1 {
			if len(parentProxy) == 0 {
				ctx.SetContextErrorWithType(err2, TunnelWriteTargetConnFinish)
			} else {
				ctx.SetPoolContextErrorWithType(err2, TunnelWriteTargetConnFinish, parentProxy[0])
			}
		}
	}
	ctx.ReqLength += written2
	targetConn.Close()
	clientConn.Close()
}

// DoRequest makes a request to remote server as a clent through given proxy,
// and calls responseFunc before returning the response.
// The "conn" is needed when it comes to https request, and only one conn is accepted.
func (p *Proxy) DoRequest(ctx *Context, rw http.ResponseWriter, responseFunc func(*http.Response, error), conn ...interface{}) {
	if len(conn) > 1 {
		return
	}
	var clientConn *tls.Conn
	if len(conn) == 1 {
		c := conn[0]
		clientConn, _ = c.(*tls.Conn)
	}

	if ctx.Data == nil {
		ctx.Data = make(map[interface{}]interface{})
	}
	p.delegate.BeforeRequest(ctx)
	if ctx.abort {
		ctx.SetContextErrType(BeforeRequestFail)
		return
	}
	newReq := new(http.Request)
	*newReq = *ctx.Req
	newReq.Header = CloneHeader(newReq.Header)
	// When server reads http request it sets req.Close to true if
	// "Connection" header contains "close".
	// https://github.com/golang/go/blob/master/src/net/http/request.go#L1080
	// Later, transfer.go adds "Connection: close" back when req.Close is true
	// https://github.com/golang/go/blob/master/src/net/http/transfer.go#L275
	// That's why tests that checks "Connection: close" removal fail
	if newReq.Header.Get("Connection") == "close" {
		newReq.Close = false
	}
	removeMITMHeaders(newReq.Header)
	removeConnectionHeaders(newReq.Header)
	removeHopHeaders(newReq.Header)

	// p.transport.ForceAttemptHTTP2 = true // for HTTP/2 test
	var parentProxyURL *url.URL
	var err error
	if ctx.Hijack {
		parentProxyURL, err = p.delegate.ParentProxy(ctx, clientConn)
	} else {
		parentProxyURL, err = p.delegate.ParentProxy(ctx, rw)
	}
	if ctx.abort {
		ctx.SetContextErrType(ParentProxyFail)
		return
	}

	type CtxKey int
	var pkey CtxKey = 0
	fakeCtx := context.WithValue(newReq.Context(), pkey, parentProxyURL)
	newReq = newReq.Clone(fakeCtx)

	dump, dumperr := httputil.DumpRequestOut(newReq, true)
	if dumperr != nil {
		Logger.Errorf("DumpRequestOut failed %s", dumperr)
	} else {
		ctx.ReqLength += int64(len(dump))
	}

	tr := p.transport
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		ctx := req.Context()
		pURL := ctx.Value(pkey).(*url.URL)
		// req = req.Clone(context.Background())
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				Logger.Infof("Got conn: %+v", connInfo)
			},
			DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
				Logger.Infof("DNS done, info: %+v", dnsInfo)
			},
			GotFirstResponseByte: func() {
				Logger.Infof("GotFirstResponseByte: %+v", time.Now())
			},
		}
		req = req.Clone(httptrace.WithClientTrace(context.Background(), trace))
		return pURL, err
	}

	resp, err := tr.RoundTrip(newReq)

	respWrapper := &ResponseWrapper{
		Resp: resp,
		Err:  err,
	}

	p.delegate.BeforeResponse(ctx, respWrapper)
	if ctx.abort {
		ctx.SetContextErrType(BeforeResponseFail)
		return
	}
	if err == nil {
		removeConnectionHeaders(resp.Header)
		removeHopHeaders(resp.Header)
	}
	responseFunc(resp, err)
}

// hijacker gets the underlying connection of an http.ResponseWriter
func hijacker(rw http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacker is not supported")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijacker failed: %s", err)
	}

	return conn, nil
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

func removeHopHeaders(h http.Header) {
	for _, item := range hopHeaders {
		if h.Get(item) != "" {
			h.Del(item)
		}
	}
}

func removeMITMHeaders(h http.Header) {
	if c := h.Get("MITM"); c != "" {
		h.Del("MITM")
	}
}

// CopyHeader shallow copy.
func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// CloneHeader deep copy.
func CloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// CloneBody deep copy.
func CloneBody(b io.ReadCloser) (r io.ReadCloser, body []byte, err error) {
	if b == nil {
		return http.NoBody, nil, nil
	}
	body, err = ioutil.ReadAll(b)
	if err != nil {
		return http.NoBody, nil, err
	}
	r = ioutil.NopCloser(bytes.NewReader(body))

	return r, body, nil
}

func (p *Proxy) proxyHTTPWithConnPool(ctx *Context, rw http.ResponseWriter) {
	ctx.Req.URL.Scheme = "http"

	if ctx.Data == nil {
		ctx.Data = make(map[interface{}]interface{})
	}

	newReq := new(http.Request)
	*newReq = *ctx.Req
	newReq.Header = CloneHeader(newReq.Header)
	// When server reads http request it sets req.Close to true if
	// "Connection" header contains "close".
	// https://github.com/golang/go/blob/master/src/net/http/request.go#L1080
	// Later, transfer.go adds "Connection: close" back when req.Close is true
	// https://github.com/golang/go/blob/master/src/net/http/transfer.go#L275
	// That's why tests that checks "Connection: close" removal fail
	if newReq.Header.Get("Connection") == "close" {
		newReq.Close = false
	}
	removeMITMHeaders(newReq.Header)
	removeConnectionHeaders(newReq.Header)
	removeHopHeaders(newReq.Header)

	poolChoices, err := p.delegate.GetConnPool(ctx)
	if err != nil {
		Logger.Errorf("proxyHTTPWithConnPool %s GetConnPool failed: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		WriteProxyErrorToResponseBody(ctx, rw, http.StatusBadGateway, fmt.Sprintf("proxyHTTPWithConnPool %s GetConnPool failed: %s", ctx.Req.URL.Host, err), "")
		ctx.SetPoolContextErrorWithType(err, PoolGetParentProxyFail)
		return
	}

	work := false
	for range poolChoices {
		// pool is not actully used to connect parent proxy,
		// it's just used to show whether a connection to it is performing well.
		// I know it's weird, and it will be fixed in the future.

		choice, err := randutil.WeightedChoice(poolChoices)
		pool := choice.Item.(ConnPool)
		parentProxyURL := pool.GetRemoteAddrURL()
		proxyTag := pool.GetTag()
		for i := range poolChoices {
			pl := poolChoices[i].Item.(ConnPool)
			if pl.GetTag() == proxyTag {
				poolChoices[i].Weight = 0
				break
			}
		}

		type CtxKey int
		var pkey CtxKey = 0
		fakeCtx := context.WithValue(newReq.Context(), pkey, parentProxyURL)
		newReq = newReq.Clone(fakeCtx)

		dump, dumperr := httputil.DumpRequestOut(newReq, true)
		if dumperr != nil {
			Logger.Errorf("DumpRequestOut failed %s", dumperr)
		} else {
			ctx.ReqLength += int64(len(dump))
		}

		tr := p.transport
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			ctx := req.Context()
			pURL := ctx.Value(pkey).(*url.URL)
			// req = req.Clone(context.Background())
			trace := &httptrace.ClientTrace{
				GotConn: func(connInfo httptrace.GotConnInfo) {
					Logger.Infof("Got conn: %+v", connInfo)
				},
				DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
					Logger.Infof("DNS done, info: %+v", dnsInfo)
				},
				GotFirstResponseByte: func() {
					Logger.Infof("GotFirstResponseByte: %+v", time.Now())
				},
			}
			req = req.Clone(httptrace.WithClientTrace(context.Background(), trace))
			return pURL, err
		}

		resp, err := tr.RoundTrip(newReq)
		p.delegate.BeforeResponse(ctx, &ResponseInfo{
			Resp:        resp,
			Err:         err,
			ParentProxy: parentProxyURL,
			Pool:        pool,
		})
		if ctx.abort {
			ctx.SetPoolContextErrorWithType(nil, BeforeRequestFail)
			return
		}

		if err != nil {
			Logger.Errorf("proxyHTTPWithConnPool %s RoundTrip failed: %s", ctx.Req.URL, err)
			ctx.SetPoolContextErrorWithType(err, PoolRoundTripFail, proxyTag)
			continue
		}
		removeConnectionHeaders(resp.Header)
		removeHopHeaders(resp.Header)

		// defer resp.Body.Close() is not used as it's in a loop.
		p.delegate.DuringResponse(ctx, resp)

		buf := make([]byte, defaultHTTPResponsePeekSize+1) // max acceptable size is defaultHTTPResponsePeekSize bytes.
		n, err := io.ReadFull(resp.Body, buf)
		switch err {
		case nil:
		case io.ErrUnexpectedEOF:
		case io.EOF:
			n = 0
		// Only errors that are not listed above will be treated as real error
		default:
			Logger.Errorf("proxyHTTPWithConnPool %s ReadFull failed: %s", ctx.Req.URL, err)
			ctx.SetPoolContextErrorWithType(err, PoolReadRemoteFail, proxyTag)
			resp.Body.Close()
			continue
		}
		buf = buf[:n]
		if resp.StatusCode != http.StatusTooManyRequests {
			if resp.StatusCode == http.StatusOK || !strings.Contains(string(buf), internalErr) {
				// No need to retry, just return what we get to rw.
				work = true
				CopyHeader(rw.Header(), resp.Header)
				rw.WriteHeader(resp.StatusCode)
				m, err := rw.Write(buf)
				ctx.RespLength += int64(m)
				if err != nil || n != m {
					if err != nil {
						Logger.Errorf("proxyHTTPWithConnPool %s first part write client failed:", ctx.Req.URL, err)
						ctx.SetPoolContextErrorWithType(err, PoolWriteClientFail, proxyTag)
					} else {
						Logger.Errorf("proxyHTTPWithConnPool %s partial write, read: %d, write: %d", ctx.Req.URL, n, m)
						ctx.SetPoolContextErrorWithType(fmt.Errorf("proxyHTTPWithConnPool %s partial write, read: %d, write: %d", ctx.Req.URL, n, m), PoolWriteClientFail, proxyTag)
					}
					resp.Body.Close()
					break
				}
				written, err := io.Copy(rw, resp.Body)
				ctx.RespLength += written
				if err != nil {
					Logger.Errorf("proxyHTTPWithConnPool %s write client failed: %s", ctx.Req.URL, err)
					ctx.SetPoolContextErrorWithType(err, PoolWriteClientFail, proxyTag)
					resp.Body.Close()
					break
				}
				ctx.SetPoolContextErrorWithType(fmt.Errorf("HTTP Regular finish"), PoolHTTPRegularFinish, proxyTag)
				resp.Body.Close()
				break
			}
		}
		// Retry
		if resp.StatusCode == http.StatusTooManyRequests {
			ctx.SetPoolContextErrorWithType(fmt.Errorf("errCode:429 errMsg:Acquire proxy failed : no available proxy"), PoolParentProxyFail, proxyTag)
		} else {
			m := make(map[string]interface{})
			err = json.Unmarshal(buf, &m)
			if err != nil {
				Logger.Errorf("proxyHTTPWithConnPool %s Unmarshal resp body failed, body: %s, err: %s", ctx.Req.URL, buf, err)
			} else {
				ctx.SetPoolContextErrorWithType(fmt.Errorf("errCode:%d errMsg:%s", int(m["errCode"].(float64)), m["errMsg"].(string)), PoolParentProxyFail, proxyTag)
			}
		}
		resp.Body.Close()
	}
	if !work {
		// No parentProxyURL works, just return http.StatusTooManyRequests
		Logger.Errorf("proxyHTTPWithConnPool %s cannot find working parent proxy to forward request", ctx.Req.URL.Host)
		rw.WriteHeader(http.StatusTooManyRequests)
		WriteProxyErrorToResponseBody(ctx, rw, http.StatusTooManyRequests, fmt.Sprintf("proxyHTTPWithConnPool %s cannot find working parent proxy to forward request", ctx.Req.URL.Host), tooManyRequests)
		ctx.SetPoolContextErrorWithType(nil, PoolNoAvailableParentProxyFail)
	}
}

func (p *Proxy) proxyTunnelWithConnPool(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		Logger.Errorf("proxyTunnelWithConnPool hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		WriteProxyErrorToResponseBody(ctx, rw, http.StatusBadGateway, fmt.Sprintf("proxyTunnelWithConnPool hijack client connection failed: %s", err), "")
		ctx.SetPoolContextErrorWithType(err, TunnelHijackClientConnFail)
		return
	}
	ctx.Hijack = true
	defer clientConn.Close()

	poolChoices, err := p.delegate.GetConnPool(ctx)
	if err != nil {
		Logger.Errorf("proxyTunnelWithConnPool %s GetConnPool failed: %s", ctx.Req.URL.Host, err)
		WriteProxyErrorToResponseBody(ctx, clientConn, http.StatusBadGateway, fmt.Sprintf("proxyTunnelWithConnPool %s GetConnPool failed: %s", ctx.Req.URL.Host, err), badGateway)
		ctx.SetPoolContextErrorWithType(err, PoolGetConnPoolFail)
		return
	}
	work := false

	for range poolChoices {
		choice, err := randutil.WeightedChoice(poolChoices)
		pool := choice.Item.(ConnPool)
		parentProxyURL := pool.GetRemoteAddrURL()
		proxyTag := pool.GetTag()
		for i := range poolChoices {
			pl := poolChoices[i].Item.(ConnPool)
			if pl.GetTag() == proxyTag {
				poolChoices[i].Weight = 0
				break
			}
		}

		// targetConn, err := net.DialTimeout("tcp", parentProxyURL.Host, defaultTargetConnectTimeout)
		targetConn, err := pool.GetWithTimeout(defaultTargetConnectTimeout)

		p.delegate.BeforeResponse(ctx, &TunnelInfo{
			Client:      clientConn,
			Target:      targetConn,
			Err:         err,
			ParentProxy: parentProxyURL,
			Pool:        pool,
		})
		if ctx.abort {
			ctx.SetPoolContextErrorWithType(nil, BeforeRequestFail)
			return
		}
		if err != nil {
			Logger.Errorf("proxyTunnelWithConnPool %s get connection to %s(%s) failed: %s", ctx.Req.URL.Host, parentProxyURL.Host, proxyTag, err)
			ctx.SetPoolContextErrorWithType(err, PoolGetConnFail, proxyTag)
			continue
		}
		// defer targetConn.Close is not used as it's in a loop

		err = makeTunnelRequestWithAuth(ctx, parentProxyURL, targetConn)

		p.delegate.DuringResponse(ctx, &TunnelInfo{Client: clientConn, Target: targetConn, Err: err, ParentProxy: parentProxyURL, Pool: pool}) // targetConn could be closed in this method
		if err != nil {
			Logger.Errorf("proxyTunnelWithConnPool %s make connect request to %s(%s) failed: %s", ctx.Req.URL.Host, parentProxyURL.Host, proxyTag, err)
			ctx.SetPoolContextErrorWithType(err, PoolWriteTargetConnFail, proxyTag)
			targetConn.Close()
			continue
		}

		connectResult := make([]byte, defaultHTTPResponsePeekSize) // buffer for http response header and body
		n, err := targetConn.Read(connectResult[:])

		p.delegate.DuringResponse(ctx, &TunnelInfo{Client: clientConn, Target: targetConn, Err: err, ParentProxy: parentProxyURL, Pool: pool}) // targetConn could be closed in this method
		if err != nil {
			Logger.Errorf("proxyTunnelWithConnPool %s read error: %s", ctx.Req.URL.Host, err)
			ctx.SetPoolContextErrorWithType(err, PoolReadTargetFail, proxyTag)
			targetConn.Close()
			continue
		}

		// "HTTP/X.X 200 OK" takes 15 bytes
		if string(connectResult[8:13]) != " 429 " {
			if string(connectResult[8:15]) == " 200 OK" || !strings.Contains(string(connectResult), internalErr) {
				work = true
				m, err := clientConn.Write(connectResult[:n])
				ctx.RespLength += int64(m)
				if err != nil || n != m {
					if err != nil {
						Logger.Errorf("proxyTunnelWithConnPool %s first part write client failed:", ctx.Req.URL.Host, err)
						ctx.SetPoolContextErrorWithType(err, PoolWriteClientFail, proxyTag)
					} else {
						Logger.Errorf("proxyTunnelWithConnPool %s partial write, read: %d, write: %d", ctx.Req.URL.Host, n, m)
						ctx.SetPoolContextErrorWithType(fmt.Errorf("proxyTunnelWithConnPool %s partial write, read: %d, write: %d", ctx.Req.URL.Host, n, m), PoolWriteClientFail, proxyTag)
					}
					targetConn.Close()
					break
				}
				transfer(ctx, clientConn, targetConn, proxyTag)
				targetConn.Close()
				break
			}
		}
		// Retry
		if string(connectResult[8:13]) == " 429 " {
			ctx.SetPoolContextErrorWithType(fmt.Errorf("errCode:429 errMsg:Acquire proxy failed : no available proxy"), PoolParentProxyFail, proxyTag)
		} else {
			mbuf := make(map[string]interface{})
			i := strings.Index(string(connectResult), "{")
			err = json.Unmarshal(connectResult[i:n], &mbuf)
			if err != nil {
				Logger.Errorf("proxyTunnelWithConnPool %s Unmarshal connectResult failed, body: %s, err: %s", ctx.Req.URL.Host, connectResult[i:n], err)
			} else {
				ctx.SetPoolContextErrorWithType(fmt.Errorf("errCode:%d errMsg:%s", int(mbuf["errCode"].(float64)), mbuf["errMsg"].(string)), PoolParentProxyFail, proxyTag)
			}
		}
		targetConn.Close()
	}
	if !work {
		// No parentProxyURL works, just return http.StatusTooManyRequests
		Logger.Errorf("proxyTunnelWithConnPool %s cannot find working parent proxy to forward request", ctx.Req.URL.Host)
		WriteProxyErrorToResponseBody(ctx, clientConn, http.StatusTooManyRequests, fmt.Sprintf("proxyTunnelWithConnPool %s cannot find working parent proxy to forward request", ctx.Req.URL.Host), tooManyRequests)
		ctx.SetPoolContextErrorWithType(nil, PoolNoAvailableParentProxyFail)
	}
}

func headerContains(header http.Header, name string, value string) bool {
	for _, v := range header[name] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(value, strings.TrimSpace(s)) {
				return true
			}
		}
	}
	return false
}

func isWebSocketRequest(r *http.Request) bool {
	return headerContains(r.Header, "Connection", "upgrade") &&
		headerContains(r.Header, "Upgrade", "websocket")
}

func (p *Proxy) websocketHandshake(ctx *Context, req *http.Request, targetConn io.ReadWriter, clientConn io.ReadWriter) error {
	// write handshake request to target
	err := req.Write(targetConn)
	if err != nil {
		Logger.Errorf("websocketHandshake %s write targetConn failed: %s", req.URL.Host, err)
		return fmt.Errorf("websocketHandshake %s write targetConn failed: %s", req.URL.Host, err)
	}

	targetTLSReader := bufio.NewReader(targetConn)

	// Read handshake response from target
	resp, err := http.ReadResponse(targetTLSReader, req)
	if err != nil {
		Logger.Errorf("websocketHandshake %s read handhsake response failed: %s", req.URL.Host, err)
		return fmt.Errorf("websocketHandshake %s write targetConn failed: %s", req.URL.Host, err)
	}

	// TODO: Do sth. to resp

	// Proxy handshake back to client
	err = resp.Write(clientConn)
	if err != nil {
		Logger.Errorf("websocketHandshake %s write handhsake response failed: %s", req.URL.Host, err)
		return fmt.Errorf("websocketHandshake %s write handhsake response failed: %s", req.URL.Host, err)
	}
	return nil
}

func (p *Proxy) serveWebsocket(ctx *Context, rw http.ResponseWriter, req *http.Request) {
	parentProxyURL, err := p.delegate.ParentProxy(ctx, rw)
	if ctx.abort {
		ctx.SetContextErrType(ParentProxyFail)
		return
	}

	ctx.Req.URL.Scheme = "ws"
	// targetURL := url.URL{Scheme: "ws", Host: req.URL.Host, Path: req.URL.Path}

	targetAddr := ctx.Req.URL.Host
	if parentProxyURL != nil {
		targetAddr = parentProxyURL.Host
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)
	if err != nil {
		Logger.Errorf("serveWebsocket %s dial targetURL failed: %s", ctx.Req.URL, err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPWebsocketDailFail)
		return
	}
	defer targetConn.Close()

	// Connect to Client
	hj, ok := rw.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		Logger.Errorf("serveWebsocket hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPWebsocketHijackFail)
		return
	}
	ctx.Hijack = true
	clientConn.Close()

	// Perform handshake
	if err := p.websocketHandshake(ctx, req, targetConn, clientConn); err != nil {
		Logger.Errorf("serveWebsocket %s handshake failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPWebsocketHandshakeFail)
		return
	}

	// Proxy ws connection
	transfer(ctx, clientConn, targetConn)
}

// TODO: should remove some headers before sending it to remote server or proxy
func (p *Proxy) serveWebsocketTLS(ctx *Context, rw http.ResponseWriter, req *http.Request) {
	parentProxyURL, err := p.delegate.ParentProxy(ctx, rw)
	if ctx.abort {
		ctx.SetContextErrType(ParentProxyFail)
		return
	}

	tlsConfig, err := p.cert.GenerateTLSConfig(ctx.Req.URL.Host)
	if err != nil {
		Logger.Errorf("serveWebsocketTLS %s generate tlsConfig failed: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPSWebsocketGenerateTLSConfigFail)
		return
	}

	clientConn, err := hijacker(rw)
	if err != nil {
		Logger.Errorf("serveWebsocketTLS hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPSWebsocketHijackFail)
		return
	}
	ctx.Hijack = true
	defer clientConn.Close()

	_, err = clientConn.Write(tunnelEstablishedResponseLine)
	if err != nil {
		Logger.Errorf("serveWebsocketTLS %s write message failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSWebsocketWriteEstRespFail)
		return
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	// Normal https handshake
	if err := tlsClientConn.Handshake(); err != nil {
		Logger.Errorf("serveWebsocketTLS %s handshake failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSWebsocketTLSClientConnHandshakeFail)
		return
	}

	// After https handshake, read the client's request
	buf := bufio.NewReader(tlsClientConn)
	wsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			Logger.Errorf("serveWebsocketTLS %s read client request failed: %s", ctx.Req.URL.Host, err)
			ctx.SetContextErrorWithType(err, HTTPSWebsocketReadReqFromBufFail)
		}
		return
	}

	// Dail the remote server, could be another proxy
	dialAddr := wsReq.URL.Host
	if parentProxyURL != nil {
		dialAddr = parentProxyURL.Host
	}

	dialer := &net.Dialer{
		Timeout: defaultTargetConnectTimeout,
	}
	tlsConfig.InsecureSkipVerify = true
	targetConn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, tlsConfig)
	// targetConn, err := tls.Dial("tcp", dialAddr, tlsConfig)
	if err != nil {
		Logger.Errorf("serveWebsocket %s dial targetURL failed: %s", ctx.Req.URL, err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPSWebsocketDailFail)
		return
	}
	defer targetConn.Close()

	// wsReq.RemoteAddr = ctx.Req.RemoteAddr
	wsReq.URL.Scheme = "wss"
	wsReq.URL.Host = wsReq.Host

	ctx.Req = wsReq

	// Perform handshake
	if err := p.websocketHandshake(ctx, wsReq, targetConn, clientConn); err != nil {
		Logger.Errorf("serveWebsocket %s handshake failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSWebsocketHandshakeFail)
		return
	}

	// Proxy ws connection
	transfer(ctx, clientConn, targetConn)
}

func (p *Proxy) proxyHTTPWebsocket(ctx *Context, rw http.ResponseWriter) {
	r := ctx.Req
	Logger.Infof("Request needs websocket upgrade %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())
	p.serveWebsocket(ctx, rw, r)
}

func (p *Proxy) proxyHTTPSWebsocket(ctx *Context, rw http.ResponseWriter) {
	r := ctx.Req
	Logger.Infof("Request needs websocket upgrade %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())
	p.serveWebsocketTLS(ctx, rw, r)
}
