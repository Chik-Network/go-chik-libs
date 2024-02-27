package types

// CoinRecord type
// https://github.com/Chik-Network/chik-blockchain/blob/main/chik/types/coin_record.py#L15
// @TODO Streamable
type CoinRecord struct {
	Coin                Coin      `json:"coin"`
	ConfirmedBlockIndex uint32    `json:"confirmed_block_index"`
	SpentBlockIndex     uint32    `json:"spent_block_index"`
	Coinbase            bool      `json:"coinbase"`
	Timestamp           Timestamp `json:"timestamp"`
}

// Spent returns whether this coin has been spent
// See https://github.com/Chik-Network/chik-blockchain/blob/main/chik/types/coin_record.py#L28
func (cr *CoinRecord) Spent() bool {
	return cr.SpentBlockIndex > 0
}
