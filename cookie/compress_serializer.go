package cookie

import (
	"bytes"
	"compress/gzip"
	"io"
	"log"

	"github.com/gorilla/securecookie"
)

type compressSerializer struct {
	inner securecookie.Serializer
}

// Deserialize implements securecookie.Serializer.
func (c *compressSerializer) Deserialize(src []byte, dst interface{}) error {
	reader, err := gzip.NewReader(bytes.NewBuffer(src))
	if err != nil {
		return err
	}
	src, err = io.ReadAll(reader)
	if err != nil {
		return err
	}
	return c.inner.Deserialize(src, dst)
}

// Serialize implements securecookie.Serializer.
func (c *compressSerializer) Serialize(src interface{}) ([]byte, error) {
	out, err := c.inner.Serialize(src)
	if err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	_, err = gzipWriter.Write(out)
	if err != nil {
		return nil, err
	}
	gzipWriter.Close()
	log.Printf("orig=%d, compressed=%d", len(out), compressed.Len())
	return compressed.Bytes(), nil
}

var _ securecookie.Serializer = &compressSerializer{}

func newCompressSerializer() *compressSerializer {
	return &compressSerializer{
		inner: securecookie.GobEncoder{},
	}
}
