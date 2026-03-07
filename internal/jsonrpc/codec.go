package jsonrpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// Scanner は NDJSON ストリームから JSON-RPC メッセージを読み取る。
type Scanner struct {
	scanner *bufio.Scanner
	msg     *Message
	raw     []byte
	err     error
}

// NewScanner は io.Reader から NDJSON を読み取る Scanner を生成する。
func NewScanner(r io.Reader) *Scanner {
	s := bufio.NewScanner(r)
	// 1MB バッファ — 大きなツール応答に対応
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	return &Scanner{scanner: s}
}

// Scan は次のメッセージを読み取る。成功時 true を返す。
// 空行はスキップする。JSON パースに失敗した場合は msg=nil, raw に生バイトを保持する。
func (s *Scanner) Scan() bool {
	for s.scanner.Scan() {
		line := s.scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// 生バイトのコピーを保持（scanner は内部バッファを再利用する）
		s.raw = make([]byte, len(line))
		copy(s.raw, line)

		var msg Message
		if err := json.Unmarshal(s.raw, &msg); err != nil {
			// パース失敗 — fail-open: 生バイトのみ保持
			s.msg = nil
			return true
		}
		s.msg = &msg
		return true
	}
	s.err = s.scanner.Err()
	return false
}

// Message は最後に読み取ったパース済みメッセージを返す。
// JSON パースに失敗した場合は nil。
func (s *Scanner) Message() *Message {
	return s.msg
}

// Raw は最後に読み取った生バイトを返す。
func (s *Scanner) Raw() []byte {
	return s.raw
}

// Err はスキャン中に発生したエラーを返す。io.EOF は nil として返される。
func (s *Scanner) Err() error {
	return s.err
}

// Encode は Message を JSON シリアライズして w に NDJSON 行として書き込む。
func Encode(w io.Writer, msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("jsonrpc encode: %w", err)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// EncodeRaw は生バイトに改行を付与して w に書き込む。
// 再シリアライズを回避し、元のバイト列をそのまま転送する。
func EncodeRaw(w io.Writer, raw []byte) error {
	buf := make([]byte, len(raw)+1)
	copy(buf, raw)
	buf[len(raw)] = '\n'
	_, err := w.Write(buf)
	return err
}
