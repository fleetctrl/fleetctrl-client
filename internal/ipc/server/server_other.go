//go:build !windows

package server

import (
	"context"
	"errors"

	"KiskaLE/RustDesk-ID/internal/ipc/protocol"
)

type Server struct{}

func New(*protocol.Handler) *Server { return &Server{} }
func (*Server) Serve(context.Context) error {
	return errors.New("FleetCtrl named pipe server is only available on Windows")
}
