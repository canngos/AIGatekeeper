package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// BodyLimits bounds how much request body is buffered for inspection.
type BodyLimits struct {
	MaxBodyBytes    int64 // raw bytes as received
	MaxDecodedBytes int64 // after Content-Encoding decoding
}

// ErrDecodedTooLarge is recorded when a compressed body inflates past the cap.
var ErrDecodedTooLarge = errors.New("decoded request body exceeds limit")

// ReadBody buffers the body of inspectable requests to intercepted
// services, decodes gzip/deflate/br, and records the raw bytes on the
// transaction so later stages can scan the text and the forwarder can relay
// the original bytes unchanged.
func ReadBody(limits BodyLimits) Middleware {
	if limits.MaxBodyBytes <= 0 {
		limits.MaxBodyBytes = 8 << 20
	}
	if limits.MaxDecodedBytes <= 0 {
		limits.MaxDecodedBytes = limits.MaxBodyBytes * 4
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := TransactionFrom(r.Context())
			if tx == nil || tx.Service == nil || tx.Passthrough || !hasInspectableBody(r) {
				next.ServeHTTP(w, r)
				return
			}

			data, err := io.ReadAll(io.LimitReader(r.Body, limits.MaxBodyBytes+1))
			if err != nil {
				tx.Err = fmt.Errorf("read request body: %w", err)
				WriteJSONError(w, http.StatusBadRequest, "body_read_failed", "AIGatekeeper could not read the request body")
				return
			}
			if int64(len(data)) > limits.MaxBodyBytes {
				// Too large to inspect. Keep the full body streamable so a
				// later policy decision of "allow" can still forward it.
				tx.Oversize = true
				tx.Encoding = contentEncoding(r)
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), r.Body))
				next.ServeHTTP(w, r)
				return
			}

			tx.RawBody = data
			r.Body = io.NopCloser(bytes.NewReader(data))
			r.ContentLength = int64(len(data))
			r.TransferEncoding = nil

			enc := contentEncoding(r)
			decoded, err := DecodeBody(data, enc, limits.MaxDecodedBytes)
			switch {
			case errors.Is(err, ErrDecodedTooLarge):
				tx.Oversize = true
				tx.Encoding = enc
			case err != nil:
				tx.ParseErr = err
				tx.Encoding = enc
			default:
				tx.Body = decoded
				tx.Encoding = enc
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasInspectableBody(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

func contentEncoding(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
}

// DecodeBody applies the Content-Encoding tokens (comma-separated, applied
// in reverse order) and enforces maxDecoded on the output.
func DecodeBody(data []byte, encoding string, maxDecoded int64) ([]byte, error) {
	if encoding == "" || encoding == "identity" {
		return data, nil
	}
	tokens := strings.Split(encoding, ",")
	cur := data
	for i := len(tokens) - 1; i >= 0; i-- {
		tok := strings.TrimSpace(tokens[i])
		if tok == "" || tok == "identity" {
			continue
		}
		reader, err := decoder(tok, bytes.NewReader(cur))
		if err != nil {
			return nil, err
		}
		out, err := io.ReadAll(io.LimitReader(reader, maxDecoded+1))
		closeIfCloser(reader)
		if err != nil {
			return nil, fmt.Errorf("decode %s body: %w", tok, err)
		}
		if int64(len(out)) > maxDecoded {
			return nil, ErrDecodedTooLarge
		}
		cur = out
	}
	return cur, nil
}

func decoder(encoding string, r *bytes.Reader) (io.Reader, error) {
	switch encoding {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("decode gzip body: %w", err)
		}
		return zr, nil
	case "deflate":
		// RFC 9110 deflate is zlib-wrapped, but some clients send raw DEFLATE.
		zr, err := zlib.NewReader(r)
		if err == nil {
			return zr, nil
		}
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return flate.NewReader(r), nil
	case "br":
		return brotli.NewReader(r), nil
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding %q", encoding)
	}
}

func closeIfCloser(r io.Reader) {
	if c, ok := r.(io.Closer); ok {
		_ = c.Close()
	}
}
