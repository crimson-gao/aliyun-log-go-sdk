package cgozstd

import (
	"sync"

	"github.com/DataDog/zstd"
)

type CgoZstdCompressor struct {
	ctxPool sync.Pool
	level   int
}

func NewCgoZstdCompressor(level int) *CgoZstdCompressor {
	res := &CgoZstdCompressor{
		level: level,
	}
	res.ctxPool = sync.Pool{
		New: func() interface{} {
			return zstd.NewCtx()
		},
	}
	zstd.NewCtx()
	return res
}

func (c *CgoZstdCompressor) Compress(src, dst []byte) ([]byte, error) {
	zstdCtx := c.ctxPool.Get().(zstd.Ctx)
	defer c.ctxPool.Put(zstdCtx)
	return zstdCtx.CompressLevel(dst, src, c.level)
}

func (c *CgoZstdCompressor) Decompress(src, dst []byte) ([]byte, error) {
	zstdCtx := c.ctxPool.Get().(zstd.Ctx)
	defer c.ctxPool.Put(zstdCtx)
	return zstdCtx.Decompress(dst, src)
}
