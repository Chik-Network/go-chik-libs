package types

import (
	"github.com/samber/mo"
)

// BlockRecord a single block record
// https://github.com/Chik-Network/chik-blockchain/blob/main/chik/consensus/block_record.py#L18
// @TODO Streamable
type BlockRecord struct {
	HeaderHash                 Bytes32                      `json:"header_hash"`
	PrevHash                   Bytes32                      `json:"prev_hash"`
	Height                     uint32                       `json:"height"`
	Weight                     Uint128                      `json:"weight"`
	TotalIters                 Uint128                      `json:"total_iters"`
	SignagePointIndex          uint8                        `json:"signage_point_index"`
	ChallengeVDFOutput         ClassgroupElement            `json:"challenge_vdf_output"`
	InfusedChallengeVDFOutput  mo.Option[ClassgroupElement] `json:"infused_challenge_vdf_output"`
	RewardInfusionNewChallenge Bytes32                      `json:"reward_infusion_new_challenge"`
	ChallengeBlockInfoHash     Bytes32                      `json:"challenge_block_info_hash"`
	SubSlotIters               uint64                       `json:"sub_slot_iters"`
	PoolPuzzleHash             Bytes32                      `json:"pool_puzzle_hash"`
	FarmerPuzzleHash           Bytes32                      `json:"farmer_puzzle_hash"`
	RequiredIters              uint64                       `json:"required_iters"`
	Deficit                    uint8                        `json:"deficit"`
	Overflow                   bool                         `json:"overflow"`
	PrevTransactionBlockHeight uint32                       `json:"prev_transaction_block_height"`

	// Transaction Block - Present if is_transaction_block
	Timestamp                mo.Option[Timestamp] `json:"timestamp"`
	PrevTransactionBlockHash mo.Option[Bytes32]   `json:"prev_transaction_block_hash"`
	Fees                     mo.Option[uint64]    `json:"fees"`
	RewardClaimsIncorporated mo.Option[[]Coin]    `json:"reward_claims_incorporated"`

	// Slot - present if this is the first SB in sub slot
	FinishedChallengeSlotHashes        mo.Option[[]Bytes32] `json:"finished_challenge_slot_hashes"`
	FinishedInfusedChallengeSlotHashes mo.Option[[]Bytes32] `json:"finished_infused_challenge_slot_hashes"`
	FinishedRewardSlotHashes           mo.Option[[]Bytes32] `json:"finished_reward_slot_hashes"`

	// Sub-epoch - present if this is the first SB after sub-epoch
	SubEpochSummaryIncluded mo.Option[SubEpochSummary] `json:"sub_epoch_summary_included"`
}

// IsTransactionBlock returns true if the block is considered a transaction block
// Only transaction blocks have timestamps
// Also matches how chik determines what is a transaction block
// https://github.com/Chik-Network/chik-blockchain/blob/dfaf70895a0923d5ac60774dd1d64a200f445e6a/chik/consensus/block_record.py#L31
func (b *BlockRecord) IsTransactionBlock() bool {
	return b.Timestamp.IsPresent()
}

// FullBlock a full block
// https://github.com/Chik-Network/chik_rs/blob/main/crates/chik-protocol/src/fullblock.rs#L13
type FullBlock struct {
	FinishedSubSlots             []EndOfSubSlotBundle               `json:"finished_sub_slots" streamable:""`
	RewardChainBlock             RewardChainBlock                   `json:"reward_chain_block" streamable:""`
	ChallengeChainSPProof        mo.Option[VDFProof]                `json:"challenge_chain_sp_proof" streamable:""`
	ChallengeChainIPProof        VDFProof                           `json:"challenge_chain_ip_proof" streamable:""`
	RewardChainSPProof           mo.Option[VDFProof]                `json:"reward_chain_sp_proof" streamable:""`
	RewardChainIPProof           VDFProof                           `json:"reward_chain_ip_proof" streamable:""`
	InfusedChallengeChainIPProof mo.Option[VDFProof]                `json:"infused_challenge_chain_ip_proof" streamable:""`
	Foliage                      Foliage                            `json:"foliage" streamable:""`
	FoliageTransactionBlock      mo.Option[FoliageTransactionBlock] `json:"foliage_transaction_block" streamable:""`
	TransactionsInfo             mo.Option[TransactionsInfo]        `json:"transactions_info" streamable:""`
	TransactionsGenerator        mo.Option[SerializedProgram]       `json:"transactions_generator" streamable:"SerializedProgram"`
	TransactionsGeneratorRefList []uint32                           `json:"transactions_generator_ref_list" streamable:""`
}

// RewardChainBlock Reward Chain Block
// https://github.com/Chik-Network/chik_rs/blob/main/crates/chik-protocol/src/reward_chain_block.rs#L24
type RewardChainBlock struct {
	Weight                     Uint128            `json:"weight" streamable:""`
	Height                     uint32             `json:"height" streamable:""`
	TotalIters                 Uint128            `json:"total_iters" streamable:""`
	SignagePointIndex          uint8              `json:"signage_point_index" streamable:""`
	POSSSCCChallengeHash       Bytes32            `json:"pos_ss_cc_challenge_hash" streamable:""`
	ProofOfSpace               ProofOfSpace       `json:"proof_of_space" streamable:""`
	ChallengeChainSPVDF        mo.Option[VDFInfo] `json:"challenge_chain_sp_vdf" streamable:""`
	ChallengeChainSPSignature  G2Element          `json:"challenge_chain_sp_signature" streamable:""`
	ChallengeChainIPVDF        VDFInfo            `json:"challenge_chain_ip_vdf" streamable:""`
	RewardChainSPVDF           mo.Option[VDFInfo] `json:"reward_chain_sp_vdf" streamable:""` // Not present for first sp in slot
	RewardChainSPSignature     G2Element          `json:"reward_chain_sp_signature" streamable:""`
	RewardChainIPVDF           VDFInfo            `json:"reward_chain_ip_vdf" streamable:""`
	InfusedChallengeChainIPVDF mo.Option[VDFInfo] `json:"infused_challenge_chain_ip_vdf" streamable:""` // Iff deficit < 16
	IsTransactionBlock         bool               `json:"is_transaction_block" streamable:""`
}

// BlockCountMetrics metrics from get_block_count_metrics endpoint
// https://github.com/Chik-Network/chik-blockchain/blob/0befdec071f49708e26c7638656874492c52600a/chik/rpc/full_node_rpc_api.py#L382
// Types are `int` in python, which is apparently unlimited in python3. Using uint64 as the largest native int in go
type BlockCountMetrics struct {
	CompactBlocks   uint64 `json:"compact_blocks"`
	UncompactBlocks uint64 `json:"uncompact_blocks"`
	HintCount       uint64 `json:"hint_count"`
}

// ReceiveBlockResult When Blockchain.receive_block(b) is called, one of these results is returned,
// showing whether the block was added to the chain (extending the peak),
// and if not, why it was not added.
// These values match values in chik blockchain. Must not be arbitrarily changed
// https://github.com/Chik-Network/chik-blockchain/blob/0befdec071f49708e26c7638656874492c52600a/chik/consensus/blockchain.py#L57
type ReceiveBlockResult uint8

const (
	// ReceiveBlockResultNewPeak Added to the peak of the blockchain
	ReceiveBlockResultNewPeak ReceiveBlockResult = 1

	// ReceiveBlockResultOrphan Added as an orphan/stale block (not a new peak of the chain)
	ReceiveBlockResultOrphan ReceiveBlockResult = 2

	// ReceiveBlockResultInvalidBlock Block was not added because it was invalid
	ReceiveBlockResultInvalidBlock ReceiveBlockResult = 3

	// ReceiveBlockResultAlreadyHaveBlock Block is already present in this blockchain
	ReceiveBlockResultAlreadyHaveBlock ReceiveBlockResult = 4

	// ReceiveBlockResultDisconnectedBlock Block's parent (previous pointer) is not in this blockchain
	ReceiveBlockResultDisconnectedBlock ReceiveBlockResult = 5
)

// BlockEvent data from block websocket event
// https://github.com/Chik-Network/chik-blockchain/blob/0befdec071f49708e26c7638656874492c52600a/chik/full_node/full_node.py#L1784
type BlockEvent struct {
	TransactionBlock              bool                          `json:"transaction_block"`
	KSize                         uint8                         `json:"k_size"`
	HeaderHash                    Bytes32                       `json:"header_hash"`
	ForkHeight                    mo.Option[uint32]             `json:"fork_height"`
	RolledBackRecords             mo.Option[uint64]             `json:"rolled_back_records"`
	Height                        uint32                        `json:"height"`
	ValidationTime                float64                       `json:"validation_time"`
	PreValidationTime             float64                       `json:"pre_validation_time"`
	BlockCost                     mo.Option[uint64]             `json:"block_cost,omitempty"`
	BlockFees                     mo.Option[uint64]             `json:"block_fees,omitempty"`
	Timestamp                     mo.Option[Timestamp]          `json:"timestamp"`
	TransactionGeneratorSizeBytes mo.Option[uint64]             `json:"transaction_generator_size_bytes,omitempty"`
	TransactionGeneratorRefList   []uint32                      `json:"transaction_generator_ref_list"`
	ReceiveBlockResult            mo.Option[ReceiveBlockResult] `json:"receive_block_result,omitempty"`
}
