//go:build windows

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"KiskaLE/RustDesk-ID/internal/ipc/protocol"

	"github.com/Microsoft/go-winio"
)

// SYSTEM and administrators receive full access; interactive users receive
// read/write access. Anonymous and network logons are explicitly denied.
const pipeSDDL = "D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

type Server struct {
	handler  *protocol.Handler
	listener net.Listener
	clients  chan struct{}
	wg       sync.WaitGroup
}

func New(handler *protocol.Handler) *Server {
	return &Server{handler: handler, clients: make(chan struct{}, protocol.MaxClients)}
}

func (s *Server) Serve(ctx context.Context) error {
	listener, err := winio.ListenPipe(protocol.PipeName, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		MessageMode:        false,
		InputBufferSize:    protocol.MaxMessage,
		OutputBufferSize:   protocol.MaxMessage,
	})
	if err != nil {
		return err
	}
	s.listener = listener
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}
		select {
		case s.clients <- struct{}{}:
			s.wg.Add(1)
			go s.serveClient(ctx, conn)
		default:
			_ = conn.Close()
		}
	}
	s.wg.Wait()
	return nil
}

func (s *Server) serveClient(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		<-s.clients
		s.wg.Done()
	}()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(io.LimitReader(conn, protocol.MaxMessage+1))
	payload, err := reader.ReadBytes('\n')
	if err != nil || len(payload) > protocol.MaxMessage {
		return
	}
	var request protocol.Request
	if json.Unmarshal(payload, &request) != nil {
		return
	}
	response := s.handler.Handle(ctx, request)
	_ = json.NewEncoder(conn).Encode(response)
}
