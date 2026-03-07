package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"

	"github.com/yuyamorita/mcpgw/internal/intercept"
	"github.com/yuyamorita/mcpgw/internal/jsonrpc"
)

// syncWriter は io.Writer をミューテックスで保護する。
// 複数のゴルーチンから安全に書き込める。
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// StdioProxy は子プロセスの stdin/stdout を介してメッセージをプロキシする。
type StdioProxy struct {
	command string
	args    []string
	chain   *intercept.Chain
	audit   *intercept.AuditLogger
}

// NewStdioProxy は StdioProxy を生成する。
// audit が nil の場合、監査ログは記録されない。
func NewStdioProxy(command string, args []string, chain *intercept.Chain, audit *intercept.AuditLogger) *StdioProxy {
	return &StdioProxy{
		command: command,
		args:    args,
		chain:   chain,
		audit:   audit,
	}
}

// Run はプロキシを起動する。
// クライアントの stdin → 子プロセスの stdin、子プロセスの stdout → クライアントの stdout。
// ctx がキャンセルされるか、いずれかのストリームが閉じると終了する。
func (p *StdioProxy) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.command, p.args...)
	cmd.Stderr = os.Stderr

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("mcpgw: stdin pipe: %w", err)
	}

	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("mcpgw: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("mcpgw: start %s: %w", p.command, err)
	}

	// clientOut を syncWriter でラップし、両ゴルーチンからの同時書き込みを直列化する
	safeOut := &syncWriter{w: clientOut}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Client → Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverIn.Close()
		if err := p.pump(ctx, clientIn, serverIn, safeOut, intercept.DirClientToServer); err != nil {
			errCh <- err
			cancel()
		}
	}()

	// Server → Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.pump(ctx, serverOut, safeOut, nil, intercept.DirServerToClient); err != nil {
			errCh <- err
			cancel()
		}
	}()

	wg.Wait()
	close(errCh)

	// pump エラーを収集（最初のエラーを返す）
	var pumpErr error
	for e := range errCh {
		if pumpErr == nil {
			pumpErr = e
		}
	}

	// 子プロセスの終了を待つ
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("mcpgw: child exited with code %d", exitErr.ExitCode())
		}
		// コンテキストキャンセルによる kill — pump エラーがあればそちらを返す
		if ctx.Err() != nil {
			return pumpErr
		}
		return fmt.Errorf("mcpgw: wait: %w", err)
	}

	return pumpErr
}

// pump は src からメッセージを読み取り、interceptor チェーンを通して dst に転送する。
// ブロック時は errDst に JSON-RPC エラーを返す（C→S 方向のみ）。
func (p *StdioProxy) pump(ctx context.Context, src io.Reader, dst io.Writer, errDst io.Writer, dir intercept.Direction) error {
	scanner := jsonrpc.NewScanner(src)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}

		msg := scanner.Message()
		raw := scanner.Raw()

		result := p.chain.Process(ctx, dir, msg, raw)

		// 最終判定結果を監査ログに記録
		if p.audit != nil {
			p.audit.Log(ctx, dir, msg, raw, result)
		}

		if result.Action == intercept.ActionBlock {
			// ブロック — C→S リクエストの場合はクライアントにエラー応答を返す
			if dir == intercept.DirClientToServer && errDst != nil && msg != nil && msg.IsRequest() {
				code := result.ErrorCode
				if code == 0 {
					code = -32600
				}
				errResp := buildErrorResponse(msg.ID, code, result.Reason)
				if err := jsonrpc.Encode(errDst, errResp); err != nil {
					slog.Error("error writing block response", "error", err)
				}
			}
			continue
		}

		// 通過 — 生バイトをそのまま転送
		if err := jsonrpc.EncodeRaw(dst, raw); err != nil {
			return fmt.Errorf("mcpgw: write %s: %w", dir, err)
		}
	}

	return scanner.Err()
}

// buildErrorResponse は JSON-RPC エラーレスポンスを構築する。
func buildErrorResponse(id json.RawMessage, code int, message string) *jsonrpc.Message {
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonrpc.ErrorObject{
			Code:    code,
			Message: message,
		},
	}
}
