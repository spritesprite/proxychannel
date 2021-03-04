package proxychannel

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
	TunnelConnectRemoteFail         = "TUNNEL_CONNECT_REMOTE_FAIL"
	TunnelWriteTargetConnFinish     = "TUNNEL_WRITE_TARGET_CONN_FINISH"
	TunnelWriteClientConnFinish     = "TUNNEL_WRITE_CLIENT_CONN_FINISH"

	PoolGetParentProxyFail         = "POOL_GET_PARENT_PROXY_FAIL"
	PoolReadRemoteFail             = "POOL_READ_REMOTE_FAIL"
	PoolWriteClientFail            = "POOL_WRITE_CLIENT_FAIL"
	PoolGetConnPoolFail            = "POOL_GET_CONN_POOL_FAIL"
	PoolNoAvailableParentProxyFail = "POOL_NO_AVAILABLE_PARENT_PROXY_FAIL"
	PoolRoundTripFail              = "POOL_ROUND_TRIP_FAIL"
	PoolParentProxyFail            = "POOL_PARENT_PROXY_FAIL"
	PoolHTTPRegularFinish          = "POOL_HTTP_REGULAR_FINISH"
	PoolGetConnFail                = "POOL_GET_CONN_FAIL"
	PoolWriteTargetConnFail        = "POOL_WRITE_TARGET_CONN_FAIL"
	PoolReadTargetFail             = "POOL_READ_TARGET_FAIL"

	HTTPWebsocketDailFail                    = "HTTP_WEBSOCKET_DAIL_FAIL"
	HTTPWebsocketHijackFail                  = "HTTP_WEBSOCKET_HIJACK_FAIL"
	HTTPWebsocketHandshakeFail               = "HTTP_WEBSOCKET_HANDSHAKE_FAIL"
	HTTPSWebsocketGenerateTLSConfigFail      = "HTTPS_WEBSOCKET_GENERATE_TLS_CONFIG_FAIL"
	HTTPSWebsocketHijackFail                 = "HTTPS_WEBSOCKET_HIJACK_FAIL"
	HTTPSWebsocketWriteEstRespFail           = "HTTPS_WEBSOCKET_WRITE_EST_RESP_FAIL"
	HTTPSWebsocketTLSClientConnHandshakeFail = "HTTPS_WEBSOCKET_TLS_CLIENT_CONN_HANDSHAKE_FAIL"
	HTTPSWebsocketReadReqFromBufFail         = "HTTPS_WEBSOCKET_READ_REQ_FROM_BUF_FAIL"
	HTTPSWebsocketDailFail                   = "HTTPS_WEBSOCKET_DAIL_FAIL"
	HTTPSWebsocketHandshakeFail              = "HTTPS_WEBSOCKET_HANDSHAKE_FAIL"

	HTTPRedialCancelTimeout   = "HTTP_REDIAL_CANCEL_TIMEOUT"
	HTTPSRedialCancelTimeout  = "HTTPS_REDIAL_CANCEL_TIMEOUT"
	TunnelRedialCancelTimeout = "TUNNEL_REDIAL_CANCEL_TIMEOUT"
)
