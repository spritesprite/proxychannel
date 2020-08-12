package cert

import "crypto/tls"

// Cache store the certificates we signed for hosts
type Cache interface {
	Set(host string, c *tls.Certificate)
	Get(host string) *tls.Certificate
}
