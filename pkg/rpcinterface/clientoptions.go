package rpcinterface

import (
	"github.com/chik-network/go-chik-libs/pkg/config"
)

// ClientOptionFunc can be used to customize a new RPC client.
type ClientOptionFunc func(client Client) error

// ConfigOptionFunc used to specify how to load configuration for the RPC client
type ConfigOptionFunc func() (*config.ChikConfig, error)
