package engine

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

const maxMIMEDepth = 20

func validateRFC822MIME(raw []byte) error {
	return validateRFC822AtDepth(raw, 0)
}

// ValidateMessageMIME uses the same validation as classification and training.
// Diagnostic callers must not log raw messages or parser errors containing headers.
func ValidateMessageMIME(raw []byte) error { return validateRFC822MIME(raw) }

func validateRFC822AtDepth(raw []byte, depth int) error {
	if depth > maxMIMEDepth {
		return fmt.Errorf("MIME structure nested too deeply")
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("RFC822: %w", err)
	}
	return validateMIMEEntity(textproto.MIMEHeader(message.Header), message.Body, depth)
}

func validateMIMEEntity(header textproto.MIMEHeader, body io.Reader, depth int) error {
	if depth > maxMIMEDepth {
		return fmt.Errorf("MIME structure nested too deeply")
	}
	contentType := header.Get("Content-Type")
	mediaType := "text/plain"
	parameters := map[string]string{}
	var err error
	if contentType != "" {
		mediaType, parameters, err = mime.ParseMediaType(contentType)
		if err != nil {
			return fmt.Errorf("Content-Type: %w", err)
		}
	}
	if disposition := header.Get("Content-Disposition"); disposition != "" {
		if _, _, err := mime.ParseMediaType(disposition); err != nil {
			return fmt.Errorf("Content-Disposition: %w", err)
		}
	}
	transferEncoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding")))
	switch transferEncoding {
	case "", "7bit", "8bit", "binary", "base64", "quoted-printable":
	default:
		return fmt.Errorf("unknown Content-Transfer-Encoding")
	}

	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := parameters["boundary"]
		if boundary == "" {
			return fmt.Errorf("multipart bez granicy boundary")
		}
		reader := multipart.NewReader(decodedMIMEBody(body, transferEncoding), boundary)
		parts := 0
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("multipart: %w", err)
			}
			parts++
			if err := validateMIMEEntity(part.Header, part, depth+1); err != nil {
				_ = part.Close()
				return err
			}
			if err := part.Close(); err != nil {
				return err
			}
		}
		if parts == 0 {
			return fmt.Errorf("pusty multipart")
		}
		return nil
	}
	if mediaType == "message/rfc822" {
		nested, err := io.ReadAll(decodedMIMEBody(body, transferEncoding))
		if err != nil {
			return err
		}
		return validateRFC822AtDepth(nested, depth+1)
	}
	_, err = io.Copy(io.Discard, decodedMIMEBody(body, transferEncoding))
	if err != nil {
		return fmt.Errorf("corrupt content %s: %w", transferEncoding, err)
	}
	return nil
}

func decodedMIMEBody(body io.Reader, transferEncoding string) io.Reader {
	switch transferEncoding {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	default:
		return body
	}
}
