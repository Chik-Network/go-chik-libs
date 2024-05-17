package types

// ClassgroupElement Classgroup Element
// https://github.com/Chik-Network/chik-blockchain/blob/main/chik/types/blockchain_format/classgroup.py#L12
// @TODO Streamable
type ClassgroupElement struct {
	Data Bytes100 `json:"data"`
}
