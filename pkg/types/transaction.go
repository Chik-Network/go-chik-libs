package types

import (
	"encoding/json"
	"fmt"
)

// TransactionRecord Single Transaction
type TransactionRecord struct {
	ConfirmedAtHeight uint32           `json:"confirmed_at_height"`
	CreatedAtTime     uint64           `json:"created_at_time"` // @TODO time.Time?
	ToPuzzleHash      *Bytes32         `json:"to_puzzle_hash"`
	Amount            uint64           `json:"amount"`
	FeeAmount         uint64           `json:"fee_amount"`
	Confirmed         bool             `json:"confirmed"`
	Sent              uint32           `json:"sent"`
	SpendBundle       *SpendBundle     `json:"spend_bundle"`
	Additions         []*Coin          `json:"additions"`
	Removals          []*Coin          `json:"removals"`
	WalletID          uint32           `json:"wallet_id"`
	SentTo            []*SentTo        `json:"sent_to"`
	TradeID           *Bytes32         `json:"trade_id"`
	Type              *TransactionType `json:"type"`
	Name              Bytes32          `json:"name"`
	// ToAddress is not on the official type, but some endpoints return it anyways
	ToAddress string `json:"to_address"`
}

// SentTo Represents the list of peers that we sent the transaction to, whether each one
// included it in the mempool, and what the error message (if any) was
// sent_to: List[Tuple[str, uint8, Optional[str]]]
type SentTo struct {
	Peer                   string
	MempoolInclusionStatus *MempoolInclusionStatus
	Error                  *string
}

// UnmarshalJSON unmarshals the SentTo tuple into the struct
func (s *SentTo) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&s.Peer, &s.MempoolInclusionStatus, &s.Error}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if g, e := len(tmp), wantLen; g != e {
		return fmt.Errorf("wrong number of fields in SentTo: %d != %d", g, e)
	}

	return nil
}

// MempoolInclusionStatus status of being included in the mempool
type MempoolInclusionStatus uint8

const (
	// MempoolInclusionStatusSuccess Successfully added to mempool
	MempoolInclusionStatusSuccess MempoolInclusionStatus = 1

	// MempoolInclusionStatusPending Pending being added to the mempool
	MempoolInclusionStatusPending MempoolInclusionStatus = 2

	// MempoolInclusionStatusFailed Failed being added to the mempool
	MempoolInclusionStatusFailed MempoolInclusionStatus = 3
)

// TransactionType type of transaction
type TransactionType uint32

const (
	// TransactionTypeIncomingTX incoming transaction
	TransactionTypeIncomingTX TransactionType = 0

	// TransactionTypeOutgoingTX outgoing transaction
	TransactionTypeOutgoingTX TransactionType = 1

	// TransactionTypeCoinbaseReward coinbase reward
	TransactionTypeCoinbaseReward TransactionType = 2

	// TransactionTypeFeeReward fee reward
	TransactionTypeFeeReward TransactionType = 3

	// TransactionTypeIncomingTrade incoming trade
	TransactionTypeIncomingTrade TransactionType = 4

	// TransactionTypeOutgoingTrade outgoing trade
	TransactionTypeOutgoingTrade TransactionType = 5
)

// SpendBundle Spend Bundle...
type SpendBundle struct {
	CoinSpends          []*CoinSpend `json:"coin_spends"`
	AggregatedSignature G2Element    `json:"aggregated_signature"`
}
