package transporttests

import "io"

// pipeConn is a bidirectional ReadWriter backed by two io.Pipes
// writes on one end come out as reads on the other
type pipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (c pipeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c pipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c pipeConn) close() {
	c.r.Close()
	c.w.Close()
}

func newPipeConn() (a, b pipeConn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return pipeConn{r2, w1}, pipeConn{r1, w2}
}
