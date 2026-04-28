package fs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

const frontmatterDelim = "---"

// ParseFrontmatter splits a markdown file into a YAML frontmatter map and
// the remaining body. A file is considered to have frontmatter iff its
// first line is exactly "---". The closing fence is the next line that is
// exactly "---". A "---" inside the body (a markdown horizontal rule) is
// not consulted because the scan stops at the first close.
func ParseFrontmatter(data []byte) (map[string]any, []byte, error) {
	if !startsWithFrontmatter(data) {
		return map[string]any{}, data, nil
	}

	rest := data[len(frontmatterDelim):]
	rest = trimOneNewline(rest)

	var yamlBuf bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(rest))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	closed := false
	consumed := 0
	for scanner.Scan() {
		line := scanner.Text()
		consumed += len(line) + 1
		if line == frontmatterDelim {
			closed = true
			break
		}
		yamlBuf.WriteString(line)
		yamlBuf.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("frontmatter: scan: %w", err)
	}
	if !closed {
		return nil, nil, fmt.Errorf("%w: frontmatter is not closed by '---'", domain.ErrValidation)
	}

	front := map[string]any{}
	if yamlBuf.Len() > 0 {
		if err := yaml.Unmarshal(yamlBuf.Bytes(), &front); err != nil {
			return nil, nil, fmt.Errorf("%w: frontmatter yaml: %v", domain.ErrValidation, err)
		}
		if front == nil {
			front = map[string]any{}
		}
	}

	body := rest
	if consumed > len(body) {
		body = nil
	} else {
		body = body[consumed:]
	}
	return front, body, nil
}

// WriteFrontmatter renders front as a YAML document delimited by "---"
// fences and concatenates body. The output always ends the frontmatter
// block with "---\n" and starts the body on the next line.
func WriteFrontmatter(front map[string]any, body []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(frontmatterDelim)
	out.WriteByte('\n')

	if len(front) > 0 {
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(2)
		if err := enc.Encode(front); err != nil {
			_ = enc.Close()
			return nil, fmt.Errorf("frontmatter: encode: %w", err)
		}
		if err := enc.Close(); err != nil {
			return nil, fmt.Errorf("frontmatter: close encoder: %w", err)
		}
	}

	bs := out.Bytes()
	bs = bytes.TrimRight(bs, "\n")
	out.Reset()
	out.Write(bs)
	out.WriteByte('\n')

	out.WriteString(frontmatterDelim)
	out.WriteByte('\n')

	if len(body) == 0 {
		return out.Bytes(), nil
	}
	if body[0] != '\n' {
		out.WriteByte('\n')
	}
	out.Write(body)
	return out.Bytes(), nil
}

func startsWithFrontmatter(data []byte) bool {
	if !bytes.HasPrefix(data, []byte(frontmatterDelim)) {
		return false
	}
	rest := data[len(frontmatterDelim):]
	if len(rest) == 0 {
		return false
	}
	switch {
	case rest[0] == '\n':
		return true
	case len(rest) >= 2 && rest[0] == '\r' && rest[1] == '\n':
		return true
	default:
		return false
	}
}

func trimOneNewline(b []byte) []byte {
	switch {
	case len(b) >= 2 && b[0] == '\r' && b[1] == '\n':
		return b[2:]
	case len(b) >= 1 && b[0] == '\n':
		return b[1:]
	default:
		return b
	}
}

// stringValue is a small helper for callers that want to read a known
// string field out of the parsed frontmatter without panicking on type
// mismatch.
//
//nolint:unused // utility kept for upcoming callers.
func stringValue(front map[string]any, key string) (string, bool) {
	v, ok := front[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}
