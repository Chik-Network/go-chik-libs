package config

import (
	// Need to embed the default config into the library
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed initial-config.yml
var initialConfig []byte

// GetChikConfig returns a struct containing the config.yaml values
func GetChikConfig() (*ChikConfig, error) {
	rootPath, err := GetChikRootPath()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(rootPath, "config", "config.yaml")
	if _, err = os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("chik config file not found at %s. Ensure CHIK_ROOT is set to the correct chik root", configPath)
	}

	return LoadConfigAtRoot(configPath, rootPath)
}

// LoadConfigAtRoot loads the given configPath into a ChikConfig
// chikRoot is required to fill the database paths in the config
func LoadConfigAtRoot(configPath, rootPath string) (*ChikConfig, error) {
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	cfg, err := LoadFromBytes(configBytes, rootPath)
	if err != nil {
		return nil, err
	}
	cfg.configPath = configPath
	return cfg, nil
}

// LoadDefaultConfig loads the initial-config bundled in go-chik-libs
func LoadDefaultConfig() (*ChikConfig, error) {
	rootPath, err := GetChikRootPath()
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(initialConfig, rootPath)
}

// LoadFromBytes loads a config from bytes.
// You will typically want to use GetChikConfig(), LoadConfigAtRoot(), or LoadDefaultConfig() instead
func LoadFromBytes(configBytes []byte, rootPath string) (*ChikConfig, error) {
	config := &ChikConfig{}

	configBytes = FixBackCompat(configBytes)
	err := yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, err
	}

	config.ChikRoot = rootPath
	config.fillDatabasePath()
	config.dealWithAnchors()

	return config, nil
}

// FixBackCompat fixes any back compat issues with configs that might have been loaded by old versions of this package
func FixBackCompat(configBytes []byte) []byte {
	// soa serial number incorrectly had string as a type for a while, and ended up quoted as a result
	// remove the quotes since it's supposed to be a number
	regex := regexp.MustCompile(`serial_number:\s*["'](\d+)["']`)
	configBytes = regex.ReplaceAll(configBytes, []byte(`serial_number: $1`))

	return configBytes
}

// Save saves the config at the path it was loaded from originally
func (c *ChikConfig) Save() error {
	if c.configPath == "" {
		return errors.New("configPath is not set on config. Save can only be used with a config that was loaded by this library. Try SavePath(path) instead")
	}

	return c.SavePath(c.configPath)
}

// SavePath saves the config at the given path
func (c *ChikConfig) SavePath(configPath string) error {
	out, err := c.SaveBytes()
	if err != nil {
		return err
	}

	err = os.WriteFile(configPath, out, 0655)
	if err != nil {
		return fmt.Errorf("error writing output file: %w", err)
	}

	return nil
}

// SaveBytes marshalls the config back down to bytes
func (c *ChikConfig) SaveBytes() ([]byte, error) {
	c.unfillDatabasePath()
	out, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("error marshalling config: %w", err)
	}
	return out, nil
}

// GetChikRootPath returns the root path for the chik installation
func GetChikRootPath() (string, error) {
	if root, ok := os.LookupEnv("CHIK_ROOT"); ok {
		return root, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	root := filepath.Join(home, ".chik", "mainnet")

	return root, nil
}

// GetFullPath returns the full path to a particular filename within CHIK_ROOT
func (c *ChikConfig) GetFullPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(c.ChikRoot, filename)
}

func (c *ChikConfig) fillDatabasePath() {
	if c.FullNode.SelectedNetwork != nil {
		c.FullNode.DatabasePath = strings.Replace(c.FullNode.DatabasePath, "CHALLENGE", *c.FullNode.SelectedNetwork, 1)
	}
}

func (c *ChikConfig) unfillDatabasePath() {
	if c.FullNode.SelectedNetwork != nil {
		c.FullNode.DatabasePath = strings.Replace(c.FullNode.DatabasePath, *c.FullNode.SelectedNetwork, "CHALLENGE", 1)
	}
}

// dealWithAnchors swaps out the distinct sections of the config with pointers to a shared instance
// When loading the config, the anchor definition in the initial-config is the canonical version. The rest will be
// changed to point back to that instance
// .self_hostname
//
//	.harvester.farmer_peers[0].host
//	.farmer.full_node_peers[0].host
//	.timelord_launcher.host
//	.timelord.vdf_clients.ip[0]
//	.timelord.full_node_peers[0].host
//	.timelord.vdf_server.host
//	.ui.daemon_host
//	.introducer.host
//	.full_node_peers[0].host
//
// .selected_network
//
//	.seeder.selected_network
//	.harvester.selected_network
//	.pool.selected_network
//	.farmer.selected_network
//	.timelord.selected_network
//	.full_node.selected_network
//	.ui.selected_network
//	.introducer.selected_network
//	.wallet.selected_network
//	.data_layer.selected_network
//
// .network_overrides
//
//	.seeder.network_overrides
//	.harvester.network_overrides
//	.pool.network_overrides
//	.farmer.network_overrides
//	.timelord.network_overrides
//	.full_node.network_overrides
//	.ui.network_overrides
//	.introducer.network_overrides
//	.wallet.network_overrides
//
// .logging
//
//	.seeder.logging
//	.harvester.logging
//	.pool.logging
//	.farmer.logging
//	.timelord_launcher.logging
//	.timelord.logging
//	.full_node.logging
//	.ui.logging
//	.introducer.logging
//	.wallet.logging
//	.data_layer.logging
func (c *ChikConfig) dealWithAnchors() {
	// For now, just doing network_overrides and selected_network
	// The rest have some edge case usefulness in not being treated like anchors always
	if c.NetworkOverrides == nil {
		c.NetworkOverrides = &NetworkOverrides{}
	}
	c.Seeder.NetworkOverrides = c.NetworkOverrides
	c.Harvester.NetworkOverrides = c.NetworkOverrides
	c.Pool.NetworkOverrides = c.NetworkOverrides
	c.Farmer.NetworkOverrides = c.NetworkOverrides
	c.Timelord.NetworkOverrides = c.NetworkOverrides
	c.FullNode.NetworkOverrides = c.NetworkOverrides
	c.UI.NetworkOverrides = c.NetworkOverrides
	c.Introducer.NetworkOverrides = c.NetworkOverrides
	c.Wallet.NetworkOverrides = c.NetworkOverrides

	if c.SelectedNetwork == nil {
		mainnet := "mainnet"
		c.SelectedNetwork = &mainnet
	}
	c.Seeder.SelectedNetwork = c.SelectedNetwork
	c.Harvester.SelectedNetwork = c.SelectedNetwork
	c.Pool.SelectedNetwork = c.SelectedNetwork
	c.Farmer.SelectedNetwork = c.SelectedNetwork
	c.Timelord.SelectedNetwork = c.SelectedNetwork
	c.FullNode.SelectedNetwork = c.SelectedNetwork
	c.UI.SelectedNetwork = c.SelectedNetwork
	c.Introducer.SelectedNetwork = c.SelectedNetwork
	c.Wallet.SelectedNetwork = c.SelectedNetwork
	c.DataLayer.SelectedNetwork = c.SelectedNetwork

	if c.Logging == nil {
		c.Logging = &LoggingConfig{}
	}
	c.Seeder.Logging = c.Logging
	c.Harvester.Logging = c.Logging
	c.Pool.Logging = c.Logging
	c.Farmer.Logging = c.Logging
	c.TimelordLauncher.Logging = c.Logging
	c.Timelord.Logging = c.Logging
	c.FullNode.Logging = c.Logging
	c.UI.Logging = c.Logging
	c.Introducer.Logging = c.Logging
	c.Wallet.Logging = c.Logging
	c.DataLayer.Logging = c.Logging
}
