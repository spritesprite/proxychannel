package proxychannel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spritesprite/proxychannel/cert"
)

const (
	defaultTargetConnectTimeout   = 5 * time.Second
	defaultTargetReadWriteTimeout = 30 * time.Second
	defaultClientReadWriteTimeout = 30 * time.Second
)

var tunnelEstablishedResponseLine = []byte(fmt.Sprintf("HTTP/1.1 %d Connection established\r\n\r\n", http.StatusOK))
var badGateway = []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", http.StatusBadGateway, http.StatusText(http.StatusBadGateway)))

func makeTunnelRequestLine(addr string) string {
	return fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", addr)
}

// Proxy is a struct that implements ServeHTTP() method
type Proxy struct {
	delegate      Delegate
	clientConnNum int32
	decryptHTTPS  bool
	cert          *cert.Certificate
	transport     *http.Transport
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

	// p.decryptHTTPS = hconf.DecryptHTTPS
	// if p.decryptHTTPS {
	// 	p.cert = cert.NewCertificate(hconf.CertCache)
	// }
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
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	} else {
		p.transport = hconf.Transport
	}
	p.transport.DisableKeepAlives = hconf.DisableKeepAlive
	// p.transport.Proxy = p.delegate.ParentProxy
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

	if ctx.Req.Method == http.MethodConnect {
		h := ctx.Req.Header.Get("MITM")
		if h == "Enabled" {
			ctx.MITM = true
			p.forwardHTTPS(ctx, rw)
		} else {
			p.forwardTunnel(ctx, rw)
		}
	} else {
		p.forwardHTTP(ctx, rw)
	}
}

// ClientConnNum gets the Client
func (p *Proxy) ClientConnNum() int32 {
	return atomic.LoadInt32(&p.clientConnNum)
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
	removeMITMHeaders(newReq.Header)
	removeConnectionHeaders(newReq.Header)
	for _, item := range hopHeaders {
		if newReq.Header.Get(item) != "" {
			newReq.Header.Del(item)
		}
	}

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

	p.transport.Proxy = func(req *http.Request) (*url.URL, error) {
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

	resp, err := p.transport.RoundTrip(newReq)

	dump, dumperr := httputil.DumpRequestOut(newReq, true)
	if dumperr != nil {
		Logger.Errorf("DumpRequestOut failed")
	} else {
		ctx.ReqLength = int64(len(dump))
	}

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
		for _, h := range hopHeaders {
			resp.Header.Del(h)
		}
	}
	responseFunc(resp, err)
}

func (p *Proxy) forwardHTTP(ctx *Context, rw http.ResponseWriter) {
	ctx.Req.URL.Scheme = "http"
	p.DoRequest(ctx, rw, func(resp *http.Response, err error) {
		if err != nil {
			Logger.Errorf("forwardHTTP %s forward request failed: %s", ctx.Req.URL, err)
			rw.WriteHeader(http.StatusBadGateway)
			ctx.SetContextErrorWithType(err, HTTPDoRequestFail)
			return
		}

		defer CloseResponseBody(ctx, resp)
		p.delegate.DuringResponse(ctx, resp)

		CopyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)

		written, err := io.Copy(rw, resp.Body)
		ctx.RespLength = written
		if err != nil {
			Logger.Errorf("forwardHTTP %s write client failed: %s", ctx.Req.URL, err)
			rw.WriteHeader(http.StatusBadGateway)
			ctx.SetContextErrorWithType(err, HTTPWriteClientFail)
			return
		}
	})
}

func (p *Proxy) forwardHTTPS(ctx *Context, rw http.ResponseWriter) {
	tlsConfig, err := p.cert.GenerateTLSConfig(ctx.Req.URL.Host)
	if err != nil {
		Logger.Errorf("forwardHTTPS %s generate tlsConfig failed: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPSGenerateTLSConfigFail)
		return
	}
	clientConn, err := hijacker(rw)
	if err != nil {
		Logger.Errorf("forwardHTTPS hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, HTTPSHijackClientConnFail)
		return
	}
	ctx.Hijack = true
	defer clientConn.Close()
	_, err = clientConn.Write(tunnelEstablishedResponseLine)
	if err != nil {
		Logger.Errorf("forwardHTTPS %s write message failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSWriteEstRespFail)
		return
	}
	// tlsConfig.NextProtos = []string{"h2", "http/1.1", "http/1.0"}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	// tlsClientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	defer CloseNetConn(ctx, tlsClientConn)
	if err := tlsClientConn.Handshake(); err != nil {
		Logger.Errorf("forwardHTTPS %s handshake failed: %s", ctx.Req.URL.Host, err)
		ctx.SetContextErrorWithType(err, HTTPSTLSClientConnHandshakeFail)
		return
	}
	buf := bufio.NewReader(tlsClientConn)
	tlsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			Logger.Errorf("forwardHTTPS %s read client request failed: %s", ctx.Req.URL.Host, err)
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
			Logger.Errorf("forwardHTTPS %s forward request failed: %s", ctx.Req.URL.Host, err)
			tlsClientConn.Write(badGateway)
			ctx.SetContextErrorWithType(err, HTTPSDoRequestFail)
			return
		}
		defer CloseResponseBody(ctx, resp)
		p.delegate.DuringResponse(ctx, resp)

		lengthWriter := &WriterWithLength{tlsClientConn, 1, 0}
		err = resp.Write(lengthWriter)
		if err != nil {
			Logger.Errorf("forwardHTTPS %s write response to client connection failed: %s", ctx.Req.URL.Host, err)
			ctx.SetContextErrorWithType(err, HTTPSWriteRespFail)
		}
		ctx.RespLength = int64(lengthWriter.Length())
	}, tlsClientConn)
}

func (p *Proxy) forwardTunnel(ctx *Context, rw http.ResponseWriter) {
	parentProxyURL, err := p.delegate.ParentProxy(ctx, rw)
	if ctx.abort {
		ctx.SetContextErrType(ParentProxyFail)
		return
	}
	clientConn, err := hijacker(rw)
	if err != nil {
		Logger.Errorf("forwardTunnel hijack client connection failed: %s", err)
		rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, TunnelHijackClientConnFail)
		return
	}
	ctx.Hijack = true
	defer clientConn.Close()

	targetAddr := ctx.Req.URL.Host
	if parentProxyURL != nil {
		targetAddr = parentProxyURL.Host
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)
	if err != nil {
		Logger.Errorf("forwardTunnel %s dial remote server failed: %s", ctx.Req.URL.Host, err)
		clientConn.Write(badGateway)
		// rw.WriteHeader(http.StatusBadGateway)
		ctx.SetContextErrorWithType(err, TunnelDialRemoteServerFail)
		return
	}
	defer CloseNetConn(ctx, targetConn)
	p.delegate.DuringResponse(ctx, targetConn)
	// clientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	// targetConn.SetDeadline(time.Now().Add(defaultTargetReadWriteTimeout))
	if parentProxyURL == nil {
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			Logger.Errorf("forwardTunnel %s write message failed: %s", ctx.Req.URL.Host, err)
			ctx.SetContextErrorWithType(err, TunnelWriteEstRespFail)
			return
		}
	} else {
		tunnelRequestLine := makeTunnelRequestLine(ctx.Req.URL.Host)
		targetConn.Write([]byte(tunnelRequestLine))
	}

	transfer(ctx, clientConn, targetConn)
}

// // transfer does two-way forwarding through connections
// func (p *Proxy) transfer(ctx *Context, src net.Conn, dst net.Conn) {
// 	go func() {
// 		// Write src
// 		written, err := io.Copy(src, dst)
// 		ctx.RespLength = written
// 		if err != nil {
// 			Logger.Errorf("1 io.Copy failed: %s", err)
// 			ctx.SetContextErrorWithType(err, TunnelWriteClientConnFail)
// 			return
// 		}
// 		src.Close()
// 		dst.Close()
// 	}()

// 	// Write dst
// 	written, err := io.Copy(dst, src)
// 	ctx.ReqLength = written
// 	if err != nil {
// 		Logger.Errorf("2 io.Copy failed: %s", err)
// 		ctx.SetContextErrorWithType(err, TunnelWriteRemoteConnFail)
// 		return
// 	}
// 	dst.Close()
// 	src.Close()
// }

// transfer does two-way forwarding through connections
func transfer(ctx *Context, src net.Conn, dst net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go copyOrWarn(ctx, src, dst, &wg)
	go copyOrWarn(ctx, dst, src, &wg)
	wg.Wait()
	src.Close()
	dst.Close()
}

func copyOrWarn(ctx *Context, dst io.Writer, src io.Reader, wg *sync.WaitGroup) {
	written, err := io.Copy(dst, src)
	if err != nil {
		Logger.Errorf("io.Copy failed: %s", err)
		ctx.SetContextErrorWithType(err, TunnelWriteConnFail)
	}
	ctx.ReqLength = written
	wg.Done()
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

// CloseResponseBody .
func CloseResponseBody(ctx *Context, r *http.Response) {
	ctx.Lock.Lock()
	defer ctx.Lock.Unlock()
	if ctx.Closed {
		return
	}
	r.Body.Close()
	ctx.Closed = true
}

// CloseNetConn .
func CloseNetConn(ctx *Context, conn net.Conn) {
	ctx.Lock.Lock()
	defer ctx.Lock.Unlock()
	if ctx.Closed {
		return
	}
	conn.Close()
	ctx.Closed = true
}
