package rpc

import (
	"log/slog"
	"net/url"
	"time"

	"github.com/chik-network/go-chik-libs/pkg/config"
	"github.com/chik-network/go-chik-libs/pkg/httpclient"
	"github.com/chik-network/go-chik-libs/pkg/rpcinterface"
	"github.com/chik-network/go-chik-libs/pkg/websocketclient"
)

// WithAutoConfig automatically loads chik config from CHIK_ROOT
func WithAutoConfig() rpcinterface.ConfigOptionFunc {
	return func() (*config.ChikConfig, error) {
		return config.GetChikConfig()
	}
}

// WithManualConfig allows supplying a manual configuration for the RPC client
func WithManualConfig(cfg config.ChikConfig) rpcinterface.ConfigOptionFunc {
	return func() (*config.ChikConfig, error) {
		return &cfg, nil
	}
}

// WithPublicConfig client option func for using public HTTP(s) servers
func WithPublicConfig() rpcinterface.ConfigOptionFunc {
	return func() (*config.ChikConfig, error) {
		return &config.ChikConfig{}, nil
	}
}

// WithSyncWebsocket is a helper to making the client and calling SetSyncMode to set the client to sync mode by default
func WithSyncWebsocket() rpcinterface.ClientOptionFunc {
	return func(c rpcinterface.Client) error {
		c.SetSyncMode()
		return nil
	}
}

// WithBaseURL sets the host for RPC requests
func WithBaseURL(url *url.URL) rpcinterface.ClientOptionFunc {
	return func(c rpcinterface.Client) error {
		return c.SetBaseURL(url)
	}
}

// WithCache specify a duration http requests should be cached for
// If unset, cache will not be used
func WithCache(validTime time.Duration) rpcinterface.ClientOptionFunc {
	return func(c rpcinterface.Client) error {
		typed, ok := c.(*httpclient.HTTPClient)
		if ok {
			typed.SetCacheValidTime(validTime)
		}

		return nil
	}
}

// WithTimeout sets the timeout for the requests
func WithTimeout(timeout time.Duration) rpcinterface.ClientOptionFunc {
	return func(c rpcinterface.Client) error {
		switch typed := c.(type) {
		case *httpclient.HTTPClient:
			typed.Timeout = timeout
		case *websocketclient.WebsocketClient:
			typed.Timeout = timeout
		}
		return nil
	}
}

// WithLogHandler sets a slog compatible log handler to be used for logging
func WithLogHandler(handler slog.Handler) rpcinterface.ClientOptionFunc {
	return func(c rpcinterface.Client) error {
		c.SetLogHandler(handler)
		return nil
	}
}
