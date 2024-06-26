package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// ChikConfig the chik config.yaml
type ChikConfig struct {
	ChikRoot        string
	DaemonPort      uint16          `yaml:"daemon_port"`
	DaemonSSL       SSLConfig       `yaml:"daemon_ssl"`
	Farmer          FarmerConfig    `yaml:"farmer"`
	FullNode        FullNodeConfig  `yaml:"full_node"`
	Harvester       HarvesterConfig `yaml:"harvester"`
	Wallet          WalletConfig    `yaml:"wallet"`
	Seeder          SeederConfig    `yaml:"seeder"`
	DataLayer       DataLayerConfig `yaml:"data_layer"`
	Timelord        TimelordConfig  `yaml:"timelord"`
	SelectedNetwork string          `yaml:"selected_network"`
}

// FarmerConfig farmer configuration section
type FarmerConfig struct {
	PortConfig `yaml:",inline"`
	SSL        SSLConfig `yaml:"ssl"`
}

// FullNodeConfig full node configuration section
type FullNodeConfig struct {
	PortConfig      `yaml:",inline"`
	SSL             SSLConfig `yaml:"ssl"`
	SelectedNetwork string    `yaml:"selected_network"`
	DatabasePath    string    `yaml:"database_path"`
	DNSServers      []string  `yaml:"dns_servers"`
}

// HarvesterConfig harvester configuration section
type HarvesterConfig struct {
	PortConfig `yaml:",inline"`
	SSL        SSLConfig `yaml:"ssl"`
}

// WalletConfig wallet configuration section
type WalletConfig struct {
	PortConfig `yaml:",inline"`
	SSL        SSLConfig `yaml:"ssl"`
}

// SeederConfig seeder configuration section
type SeederConfig struct {
	CrawlerConfig CrawlerConfig `yaml:"crawler"`
}

// CrawlerConfig is the subsection of the seeder config specific to the crawler
type CrawlerConfig struct {
	PortConfig `yaml:",inline"`
	SSL        SSLConfig `yaml:"ssl"`
}

// DataLayerConfig datalayer configuration section
type DataLayerConfig struct {
	PortConfig `yaml:",inline"`
	SSL        SSLConfig `yaml:"ssl"`
}

// TimelordConfig timelord configuration section
type TimelordConfig struct {
	PortConfig `yaml:",inline"`
	SSL        SSLConfig `yaml:"ssl"`
}

// PortConfig common port settings found in many sections of the config
type PortConfig struct {
	Port    uint16 `yaml:"port"`
	RPCPort uint16 `yaml:"rpc_port"`
}

// SSLConfig common ssl settings found in many sections of the config
type SSLConfig struct {
	PrivateCRT string `yaml:"private_crt"`
	PrivateKey string `yaml:"private_key"`
	PublicCRT  string `yaml:"public_crt"`
	PublicKey  string `yaml:"public_key"`
}

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

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	config := &ChikConfig{}

	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, err
	}

	config.ChikRoot = rootPath
	config.fillDatabasePath()

	return config, nil
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
	c.FullNode.DatabasePath = strings.Replace(c.FullNode.DatabasePath, "CHALLENGE", c.FullNode.SelectedNetwork, 1)
}
