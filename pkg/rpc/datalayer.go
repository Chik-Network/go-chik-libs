package rpc

import (
	"net/http"

	"github.com/chik-network/go-chik-libs/pkg/rpcinterface"
	"github.com/chik-network/go-chik-libs/pkg/types"
)

// DataLayerService encapsulates data layer RPC methods
type DataLayerService struct {
	client *Client
}

// NewRequest returns a new request specific to the wallet service
func (s *DataLayerService) NewRequest(rpcEndpoint rpcinterface.Endpoint, opt interface{}) (*rpcinterface.Request, error) {
	return s.client.NewRequest(rpcinterface.ServiceDataLayer, rpcEndpoint, opt)
}

// GetClient returns the active client for the service
func (s *DataLayerService) GetClient() rpcinterface.Client {
	return s.client
}

// GetNetworkInfo gets the network name and prefix from the full node
func (s *DataLayerService) GetNetworkInfo(opts *GetNetworkInfoOptions) (*GetNetworkInfoResponse, *http.Response, error) {
	return Do(s, "get_network_info", opts, &GetNetworkInfoResponse{})
}

// GetVersion returns the application version for the service
func (s *DataLayerService) GetVersion(opts *GetVersionOptions) (*GetVersionResponse, *http.Response, error) {
	return Do(s, "get_version", opts, &GetVersionResponse{})
}

// DatalayerGetSubscriptionsOptions options for get_subscriptions
type DatalayerGetSubscriptionsOptions struct{}

// DatalayerGetSubscriptionsResponse response for get_subscriptions
type DatalayerGetSubscriptionsResponse struct {
	rpcinterface.Response
	StoreIDs []string `json:"store_ids"`
}

// GetSubscriptions is just an alias for Subscriptions, since the CLI command is get_subscriptions
// Makes this easier to find
func (s *DataLayerService) GetSubscriptions(opts *DatalayerGetSubscriptionsOptions) (*DatalayerGetSubscriptionsResponse, *http.Response, error) {
	return s.Subscriptions(opts)
}

// Subscriptions calls the subscriptions endpoint to list all subscriptions
func (s *DataLayerService) Subscriptions(opts *DatalayerGetSubscriptionsOptions) (*DatalayerGetSubscriptionsResponse, *http.Response, error) {
	return Do(s, "subscriptions", opts, &DatalayerGetSubscriptionsResponse{})
}

// DatalayerGetOwnedStoresOptions Options for get_owned_stores
type DatalayerGetOwnedStoresOptions struct{}

// DatalayerGetOwnedStoresResponse Response for get_owned_stores
type DatalayerGetOwnedStoresResponse struct {
	rpcinterface.Response
	StoreIDs []string `json:"store_ids"`
}

// GetOwnedStores RPC endpoint get_owned_stores
func (s *DataLayerService) GetOwnedStores(opts *DatalayerGetOwnedStoresOptions) (*DatalayerGetOwnedStoresResponse, *http.Response, error) {
	return Do(s, "get_owned_stores", opts, &DatalayerGetOwnedStoresResponse{})
}

// DatalayerGetMirrorsOptions Options for get_mirrors
type DatalayerGetMirrorsOptions struct {
	ID string `json:"id"` // Hex String
}

// DatalayerGetMirrorsResponse Response from the get_mirrors RPC
type DatalayerGetMirrorsResponse struct {
	rpcinterface.Response
	Mirrors []types.DatalayerMirror `json:"mirrors"`
}

// GetMirrors lists the mirrors for the given datalayer store
func (s *DataLayerService) GetMirrors(opts *DatalayerGetMirrorsOptions) (*DatalayerGetMirrorsResponse, *http.Response, error) {
	return Do(s, "get_mirrors", opts, &DatalayerGetMirrorsResponse{})
}

// DatalayerDeleteMirrorOptions options for delete_mirror RPC call
type DatalayerDeleteMirrorOptions struct {
	CoinID string `json:"coin_id"` // hex string
	Fee    uint64 `json:"fee"`     // not required
}

// DatalayerDeleteMirrorResponse response data for delete_mirror
type DatalayerDeleteMirrorResponse struct {
	rpcinterface.Response
}

// DeleteMirror deletes a datalayer mirror
func (s *DataLayerService) DeleteMirror(opts *DatalayerDeleteMirrorOptions) (*DatalayerDeleteMirrorResponse, *http.Response, error) {
	return Do(s, "delete_mirror", opts, &DatalayerDeleteMirrorResponse{})
}

// DatalayerAddMirrorOptions options for delete_mirror RPC call
type DatalayerAddMirrorOptions struct {
	ID     string   `json:"id"` // hex string datastore ID
	URLs   []string `json:"urls"`
	Amount uint64   `json:"amount"`
	Fee    uint64   `json:"fee"`
}

// DatalayerAddMirrorResponse response data for add_mirror
type DatalayerAddMirrorResponse struct {
	rpcinterface.Response
}

// AddMirror deletes a datalayer mirror
func (s *DataLayerService) AddMirror(opts *DatalayerAddMirrorOptions) (*DatalayerAddMirrorResponse, *http.Response, error) {
	return Do(s, "add_mirror", opts, &DatalayerAddMirrorResponse{})
}

// DatalayerSubscribeOptions options for subscribe
type DatalayerSubscribeOptions struct {
	ID   string   `json:"id"` // hex string datastore id
	URLs []string `json:"urls,omitempty"`
}

// DatalayerSubscribeResponse Response from subscribe. Always empty aside from standard fields
type DatalayerSubscribeResponse struct {
	rpcinterface.Response
}

// Subscribe deletes a datalayer mirror
func (s *DataLayerService) Subscribe(opts *DatalayerSubscribeOptions) (*DatalayerSubscribeResponse, *http.Response, error) {
	return Do(s, "subscribe", opts, &DatalayerSubscribeResponse{})
}

// DatalayerUnsubscribeOptions options for unsubscribing to a datastore
type DatalayerUnsubscribeOptions struct {
	ID         string `json:"id"` // hex string datastore id
	RetainData bool   `json:"retain"`
}

// DatalayerUnsubscribeResponse response data for unsubscribe
type DatalayerUnsubscribeResponse struct {
	rpcinterface.Response
}

// Unsubscribe deletes a datalayer mirror
func (s *DataLayerService) Unsubscribe(opts *DatalayerUnsubscribeOptions) (*DatalayerUnsubscribeResponse, *http.Response, error) {
	return Do(s, "unsubscribe", opts, &DatalayerUnsubscribeResponse{})
}

// DatalayerGetKeysValuesOptions options for get_keys_values
type DatalayerGetKeysValuesOptions struct {
	ID string `json:"id"` // Hex String
}

// DatalayerGetKeysValuesResponse represents the response from the get_keys_values RPC endpoint
type DatalayerGetKeysValuesResponse struct {
	rpcinterface.Response
	KeysValues []types.DatalayerKeyValue `json:"keys_values"`
}

// GetKeysValues retrieves all keys and values for a given datalayer store
func (s *DataLayerService) GetKeysValues(opts *DatalayerGetKeysValuesOptions) (*DatalayerGetKeysValuesResponse, *http.Response, error) {
	return Do(s, "get_keys_values", opts, &DatalayerGetKeysValuesResponse{})
}
