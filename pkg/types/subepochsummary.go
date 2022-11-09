package types

// SubEpochSummary sub epoch summary
type SubEpochSummary struct {
	PrevSubEpochSummaryHash Bytes32 `json:"prev_subepoch_summary_hash"`
	RewardChainHash         Bytes32 `json:"reward_chain_hash"`
	NumBlocksOverflow       uint8   `json:"num_blocks_overflow"`
	NewDifficulty           uint64  `json:"new_difficulty"`
	NewSubSlotIters         uint64  `json:"new_sub_slot_iters"`
}
