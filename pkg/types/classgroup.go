package types

// ClassgroupElement Classgroup Element
// https://github.com/Chik-Network/chik_rs/blob/main/crates/chik-protocol/src/classgroup.rs#L8
type ClassgroupElement struct {
	Data Bytes100 `json:"data" streamable:""`
}
