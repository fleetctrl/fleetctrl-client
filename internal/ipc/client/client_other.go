//go:build !windows

package client

import (
	"context"
	"errors"
	"time"
)

type Client struct{ Timeout time.Duration }

func New() *Client { return &Client{Timeout: 10 * time.Second} }
func (*Client) Call(context.Context, string, any, any) error {
	return errors.New("FleetCtrl named pipe client is only available on Windows")
}
