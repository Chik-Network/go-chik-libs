package rpc

import (
	"github.com/samber/mo"

	"github.com/chik-network/go-chik-libs/pkg/rpcinterface"
)

// GetNetworkInfoOptions options for the get_network_info rpc calls
type GetNetworkInfoOptions struct{}

// GetNetworkInfoResponse common get_network_info response from all RPC services
type GetNetworkInfoResponse struct {
	rpcinterface.Response
	NetworkName   mo.Option[string] `json:"network_name"`
	NetworkPrefix mo.Option[string] `json:"network_prefix"`
}

// GetVersionOptions options for the get_version rpc calls
type GetVersionOptions struct{}

// GetVersionResponse is the response of get_version from all RPC services
type GetVersionResponse struct {
	rpcinterface.Response
	Version string `json:"version"`
}

// ServiceFullName are the full names to services that things like the daemon will recognize
type ServiceFullName string

const (
	// ServiceFullNameDaemon name of the daemon service
	ServiceFullNameDaemon ServiceFullName = "daemon"

	// ServiceFullNameDataLayer name of the data layer service
	ServiceFullNameDataLayer ServiceFullName = "chik_data_layer"

	// ServiceFullNameDataLayerHTTP name of data layer http service
	ServiceFullNameDataLayerHTTP ServiceFullName = "chik_data_layer_http"

	// ServiceFullNameWallet name of the wallet service
	ServiceFullNameWallet ServiceFullName = "chik_wallet"

	// ServiceFullNameNode name of the full node service
	ServiceFullNameNode ServiceFullName = "chik_full_node"

	// ServiceFullNameHarvester name of the harvester service
	ServiceFullNameHarvester ServiceFullName = "chik_harvester"

	// ServiceFullNameFarmer name of the farmer service
	ServiceFullNameFarmer ServiceFullName = "chik_farmer"

	// ServiceFullNameIntroducer name of the introducer service
	ServiceFullNameIntroducer ServiceFullName = "chik_introducer"

	// ServiceFullNameTimelord name of the timelord service
	ServiceFullNameTimelord ServiceFullName = "chik_timelord"

	// ServiceFullNameTimelordLauncher name of the timelord launcher service
	ServiceFullNameTimelordLauncher ServiceFullName = "chik_timelord_launcher"

	// ServiceFullNameSimulator name of the simulator service
	ServiceFullNameSimulator ServiceFullName = "chik_full_node_simulator"

	// ServiceFullNameSeeder name of the seeder service
	ServiceFullNameSeeder ServiceFullName = "chik_seeder"

	// ServiceFullNameCrawler name of the crawler service
	ServiceFullNameCrawler ServiceFullName = "chik_crawler"
)
