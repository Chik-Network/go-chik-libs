package types

import (
	"github.com/samber/mo"
)

// WebsocketBlockchainState is how blockchain_state comes across in the websockets (wrapped)
// https://github.com/Chik-Network/chik-blockchain/blob/main/chik/rpc/full_node_rpc_api.py#L123
type WebsocketBlockchainState struct {
	BlockchainState BlockchainState `json:"blockchain_state"`
}

// BlockchainState blockchain state
// https://github.com/Chik-Network/chik-blockchain/blob/main/chik/rpc/full_node_rpc_api.py#L123
type BlockchainState struct {
	Difficulty                  uint64                 `json:"difficulty"`
	GenesisChallengeInitialized bool                   `json:"genesis_challenge_initialized"`
	MempoolSize                 uint64                 `json:"mempool_size"`
	MempoolCost                 uint64                 `json:"mempool_cost"`
	MempoolMinFees              MempoolMinFees         `json:"mempool_min_fees"`
	MempoolMaxTotalCost         uint64                 `json:"mempool_max_total_cost"`
	Peak                        mo.Option[BlockRecord] `json:"peak"`
	Space                       Uint128                `json:"space"`
	SubSlotIters                uint64                 `json:"sub_slot_iters"`
	Sync                        Sync                   `json:"sync"`
	BlockMaxCost                uint64                 `json:"block_max_cost"`
}

// MempoolMinFees minimum fees to get in the mempool at varying costs
type MempoolMinFees struct {
	Cost5m float64 `json:"cost_5000000"`
}

// Sync struct within blockchain state
type Sync struct {
	SyncMode           bool   `json:"sync_mode"`
	SyncProgressHeight uint32 `json:"sync_progress_height"`
	SyncTipHeight      uint32 `json:"sync_tip_height"`
	Synced             bool   `json:"synced"`
}
