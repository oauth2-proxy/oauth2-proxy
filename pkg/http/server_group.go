package http

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// NewServerGroup creates a new Server to start and gracefully stop a collection
// of Servers.
func NewServerGroup(servers ...Server) Server {
	return &serverGroup{
		servers: servers,
	}
}

// serverGroup manages the starting and graceful shutdown of a collection of
// servers.
type serverGroup struct {
	servers []Server
}

// Start runs the servers in the server group.
func (s *serverGroup) Start(ctx context.Context) error {
	g, groupCtx := errgroup.WithContext(ctx)

	for _, server := range s.servers {
		srv := server
		g.Go(func() error {
			return srv.Start(groupCtx)
		})
	}

	return g.Wait()
}
