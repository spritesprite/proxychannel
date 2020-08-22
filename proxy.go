package proxychannel

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
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

	p.decryptHTTPS = hconf.DecryptHTTPS
	if p.decryptHTTPS {
		p.cert = cert.NewCertificate(hconf.CertCache)
	}

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
	p.transport.Proxy = p.delegate.ParentProxy
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
		Req:  req,
		Data: make(map[interface{}]interface{}),
	}
	defer p.delegate.Finish(ctx)
	p.delegate.Connect(ctx, rw)
	if ctx.abort {
		return
	}
	p.delegate.Auth(ctx, rw)
	if ctx.abort {
		return
	}

	switch {
	case ctx.Req.Method == http.MethodConnect && p.decryptHTTPS:
		p.forwardHTTPS(ctx, rw)
	case ctx.Req.Method == http.MethodConnect:
		p.forwardTunnel(ctx, rw)
	default:
		p.forwardHTTP(ctx, rw)
	}
}

// ClientConnNum gets the Client
func (p *Proxy) ClientConnNum() int32 {
	return atomic.LoadInt32(&p.clientConnNum)
}

// DoRequest 执行HTTP请求，并调用responseFunc处理response
func (p *Proxy) DoRequest(ctx *Context, responseFunc func(*http.Response, error)) {
	if ctx.Data == nil {
		ctx.Data = make(map[interface{}]interface{})
	}
	p.delegate.BeforeRequest(ctx)
	if ctx.abort {
		return
	}
	newReq := new(http.Request)
	*newReq = *ctx.Req
	newReq.Header = CloneHeader(newReq.Header)
	removeConnectionHeaders(newReq.Header)
	for _, item := range hopHeaders {
		if newReq.Header.Get(item) != "" {
			newReq.Header.Del(item)
		}
	}
	// p.transport.ForceAttemptHTTP2 = true // for test
	resp, err := p.transport.RoundTrip(newReq)
	p.delegate.BeforeResponse(ctx, resp, err)
	if ctx.abort {
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
	p.DoRequest(ctx, func(resp *http.Response, err error) {
		if err != nil {
			fmt.Println(fmt.Errorf("%s - HTTP请求错误: , 错误: %s", ctx.Req.URL, err))
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		CopyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
	})
}

func (p *Proxy) forwardHTTPS(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer clientConn.Close()
	_, err = clientConn.Write(tunnelEstablishedResponseLine)
	if err != nil {
		fmt.Println(fmt.Errorf("%s - HTTPS解密, 通知客户端隧道已连接失败, %s", ctx.Req.URL.Host, err))
		return
	}
	tlsConfig, err := p.cert.GenerateTlsConfig(ctx.Req.URL.Host)
	if err != nil {
		fmt.Println(fmt.Errorf("%s - HTTPS解密, 生成证书失败: %s", ctx.Req.URL.Host, err))
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	// tlsConfig.NextProtos = []string{"h2", "http/1.1", "http/1.0"}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	tlsClientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	defer tlsClientConn.Close()
	if err := tlsClientConn.Handshake(); err != nil {
		fmt.Println(fmt.Errorf("%s - HTTPS解密, 握手失败: %s", ctx.Req.URL.Host, err))
		return
	}
	buf := bufio.NewReader(tlsClientConn)
	tlsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			fmt.Println(fmt.Errorf("%s - HTTPS解密, 读取客户端请求失败: %s", ctx.Req.URL.Host, err))
		}
		return
	}
	tlsReq.RemoteAddr = ctx.Req.RemoteAddr
	tlsReq.URL.Scheme = "https"
	tlsReq.URL.Host = tlsReq.Host

	ctx.Req = tlsReq
	p.DoRequest(ctx, func(resp *http.Response, err error) {
		if err != nil {
			fmt.Println(fmt.Errorf("%s - HTTPS解密, 请求错误: %s", ctx.Req.URL, err))
			tlsClientConn.Write(badGateway)
			return
		}
		err = resp.Write(tlsClientConn)
		if err != nil {
			fmt.Println(fmt.Errorf("%s - HTTPS解密, response写入客户端失败, %s", ctx.Req.URL, err))
		}
		resp.Body.Close()
	})
}

// 隧道转发
func (p *Proxy) forwardTunnel(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer clientConn.Close()
	parentProxyURL, err := p.delegate.ParentProxy(ctx.Req)
	if err != nil {
		fmt.Println(fmt.Errorf("%s - 解析代理地址错误: %s", ctx.Req.URL.Host, err))
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	targetAddr := ctx.Req.URL.Host
	if parentProxyURL != nil {
		targetAddr = parentProxyURL.Host
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)
	if err != nil {
		fmt.Println(fmt.Errorf("%s - 隧道转发连接目标服务器失败: %s", ctx.Req.URL.Host, err))
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	clientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	targetConn.SetDeadline(time.Now().Add(defaultTargetReadWriteTimeout))
	if parentProxyURL == nil {
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			fmt.Println(fmt.Errorf("%s - 隧道连接成功,通知客户端错误: %s", ctx.Req.URL.Host, err))
			return
		}
	} else {
		tunnelRequestLine := makeTunnelRequestLine(ctx.Req.URL.Host)
		targetConn.Write([]byte(tunnelRequestLine))
	}

	p.transfer(clientConn, targetConn)
}

// 双向转发
func (p *Proxy) transfer(src net.Conn, dst net.Conn) {
	go func() {
		io.Copy(src, dst)
		src.Close()
		dst.Close()
	}()

	io.Copy(dst, src)
	dst.Close()
	src.Close()
}

// 获取底层连接
func hijacker(rw http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("web server不支持Hijacker")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijacker错误: %s", err)
	}

	return conn, nil
}

// CopyHeader 浅拷贝Header
func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// CloneHeader 深拷贝Header
func CloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// CloneBody 拷贝Body
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
