package proxychannel

// Reader .
type Reader interface {
	Read([]byte) (int, error)
}

// ReaderWithProtocol .
type ReaderWithProtocol struct {
	reader Reader
	length int
}

func (r *ReaderWithProtocol) Read(b []byte) (n int, err error) {
	n, err = r.Read(b)
	r.length += n
	return n, err
}
