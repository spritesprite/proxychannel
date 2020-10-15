package proxychannel

// EventType .
const (
	ConnectDone        = "CONNECT_DONE"
	AuthDone           = "AUTH_DONE"
	BeforeRequestDone  = "BEFORE_REQUEST_DONE"
	BeforeResponseDone = "BEFORE_RESPONSE_DONE"
	ParentProxyDone    = "PARENT_PROXY_DONE"
	DuringResponseDone = "DURING_RESPONSE_DONE"
	FinishDone         = "FINISH_DONE"
)

// FailEventType .
// When a request is aborted, the event should be one of the following.
const (
	ConnectFail        = "CONNECT_FAIL"
	AuthFail           = "AUTH_FAIL"
	BeforeRequestFail  = "BEFORE_REQUEST_FAIL"
	BeforeResponseFail = "BEFORE_RESPONSE_FAIL"
	ParentProxyFail    = "PARENT_PROXY_FAIL"

	HTTPDoRequestFail               = "HTTP_DO_REQUEST_FAIL"
	HTTPWriteClientFail             = "HTTP_WRITE_CLIENT_FAIL"
	HTTPSGenerateTLSConfigFail      = "HTTPS_GENERATE_TLS_CONFIG_FAIL"
	HTTPSHijackClientConnFail       = "HTTPS_HIJACK_CLIENT_CONN_FAIL"
	HTTPSWriteEstRespFail           = "HTTPS_WRITE_EST_RESP_FAIL"
	HTTPSTLSClientConnHandshakeFail = "HTTPSTLS_CLIENT_CONN_HANDSHAKE_FAIL"
	HTTPSReadReqFromBufFail         = "HTTPS_READ_REQ_FROM_BUF_FAIL"
	HTTPSDoRequestFail              = "HTTPS_DO_REQUEST_FAIL"
	HTTPSWriteRespFail              = "HTTPS_WRITE_RESP_FAIL"
	TunnelHijackClientConnFail      = "TUNNEL_HIJACK_CLIENT_CONN_FAIL"
	TunnelDialRemoteServerFail      = "TUNNEL_DIAL_REMOTE_SERVER_FAIL"
	TunnelWriteEstRespFail          = "TUNNEL_WRITE_EST_RESP_FAIL"
	TunnelWriteClientConnFail       = "TUNNEL_WRITE_CLIENT_CONN_FAIL"
	TunnelWriteRemoteConnFail       = "TUNNEL_WRITE_REMOTE_CONN_FAIL"
)
