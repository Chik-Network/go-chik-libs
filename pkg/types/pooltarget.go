package types

// PoolTarget PoolTarget
// https://github.com/Chik-Network/chik_rs/blob/main/crates/chik-protocol/src/pool_target.rs#L6
type PoolTarget struct {
	PuzzleHash Bytes32 `json:"puzzle_hash" streamable:""`
	MaxHeight  uint32  `json:"max_height" streamable:""`
}
