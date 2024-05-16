package types

import (
	"github.com/samber/mo"
)

// ProofOfSpace Proof of Space
// https://github.com/Chik-Network/chik_rs/blob/main/crates/chik-protocol/src/proof_of_space.rs#L6
type ProofOfSpace struct {
	Challenge              Bytes32              `json:"challenge" streamable:""`
	PoolPublicKey          mo.Option[G1Element] `json:"pool_public_key" streamable:""` // Only one of these two should be present
	PoolContractPuzzleHash mo.Option[Bytes32]   `json:"pool_contract_puzzle_hash" streamable:""`
	PlotPublicKey          G1Element            `json:"plot_public_key" streamable:""`
	Size                   uint8                `json:"size" streamable:""`
	Proof                  Bytes                `json:"proof" streamable:""`
}
