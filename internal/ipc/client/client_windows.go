//go:build windows

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"KiskaLE/RustDesk-ID/internal/ipc/protocol"

	"github.com/Microsoft/go-winio"
	"github.com/google/uuid"
)

type Client struct {
	Timeout time.Duration
}

func New() *Client { return &Client{Timeout: 10 * time.Second} }

func (c *Client) Call(ctx context.Context, method string, params any, result any) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, protocol.PipeName)
	if err != nil {
		return fmt.Errorf("service unavailable: %w", err)
	}
	defer conn.Close()
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	request := protocol.Request{Version: protocol.Version, RequestID: uuid.NewString(), Method: method, Params: raw}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(conn, protocol.MaxMessage+1))
	payload, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(payload) > protocol.MaxMessage {
		return fmt.Errorf("service response exceeds limit")
	}
	var response protocol.Response
	if err := json.Unmarshal(payload, &response); err != nil {
		return err
	}
	if response.Version != protocol.Version {
		return fmt.Errorf("%s: incompatible service protocol", protocol.UnsupportedVersion)
	}
	if !response.OK {
		if response.Error == nil {
			return fmt.Errorf("%s: request failed", protocol.InternalError)
		}
		return fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
	}
	encoded, err := json.Marshal(response.Result)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, result)
}
