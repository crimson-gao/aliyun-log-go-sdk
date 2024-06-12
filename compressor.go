package sls

import (
	"sync"

	cgozstd "github.com/DataDog/zstd"
	"github.com/klauspost/compress/zstd"
)

type LogEncoder interface {
	CompressType() int
	// Compress src into dst.  If you have a buffer to use, you can pass it to
	// prevent allocation.  If it is too small, or if nil is passed, a new buffer
	// will be allocated and returned.
	Compress(src, dst []byte) ([]byte, error)
}

type LogDecoder interface {
	CompressType() int
	// Decompress src into dst.  If you have a buffer to use, you can pass it to
	// prevent allocation.  If it is too small, or if nil is passed, a new buffer
	// will be allocated and returned.
	Decompress(src, dst []byte) ([]byte, error)
}

type LogCompressor interface {
	LogEncoder
	LogDecoder
}

type GoZstdCompressor struct {
	writer *zstd.Encoder
	reader *zstd.Decoder
	level  zstd.EncoderLevel
}

func NewGoZstdCompressor(level zstd.EncoderLevel) *GoZstdCompressor {
	res := &GoZstdCompressor{
		level: level,
	}
	res.writer, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(res.level))
	res.reader, _ = zstd.NewReader(nil)
	return res
}

func (c *GoZstdCompressor) CompressType() int {
	return Compress_ZSTD
}

func (c *GoZstdCompressor) Compress(src, dst []byte) ([]byte, error) {
	if dst != nil {
		return c.writer.EncodeAll(src, dst[:0]), nil
	}
	return c.writer.EncodeAll(src, nil), nil
}

func (c *GoZstdCompressor) Decompress(src, dst []byte) ([]byte, error) {
	if dst != nil {
		return c.reader.DecodeAll(src, dst[:0])
	}
	return c.reader.DecodeAll(src, nil)
}

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
			return cgozstd.NewCtx()
		},
	}
	cgozstd.NewCtx()
	return res
}

func (c *CgoZstdCompressor) CompressType() int {
	return Compress_ZSTD
}

func (c *CgoZstdCompressor) Compress(src, dst []byte) ([]byte, error) {
	zstdCtx := c.ctxPool.Get().(cgozstd.Ctx)
	defer c.ctxPool.Put(zstdCtx)
	return zstdCtx.CompressLevel(dst, src, c.level)
}

func (c *CgoZstdCompressor) Decompress(src, dst []byte) ([]byte, error) {
	zstdCtx := c.ctxPool.Get().(cgozstd.Ctx)
	defer c.ctxPool.Put(zstdCtx)
	return zstdCtx.Decompress(dst, src)
}

var DefaultZstdCompressor LogCompressor = NewGoZstdCompressor(zstd.SpeedFastest)
