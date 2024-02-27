package types

// PoolTarget PoolTarget
// https://github.com/Chik-Network/chik-blockchain/blob/main/chik/types/blockchain_format/pool_target.py#L12
// @TODO Streamable
type PoolTarget struct {
	PuzzleHash Bytes32 `json:"puzzle_hash"`
	MaxHeight  uint32  `json:"max_height"`
}
