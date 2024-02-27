package protocols_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chik-network/go-chik-libs/pkg/protocols"
	"github.com/chik-network/go-chik-libs/pkg/streamable"
)

func TestRespondPeers(t *testing.T) {
	// Has one peer in the list
	// IP 1.2.3.4
	// Port 9678
	// Timestamp 1643913969
	hexStr := "0000000100000007312e322e332e3425ce0000000061fc22f1"

	// Hex to bytes
	encodedBytes, err := hex.DecodeString(hexStr)
	assert.NoError(t, err)

	rp := &protocols.RespondPeers{}

	err = streamable.Unmarshal(encodedBytes, rp)
	assert.NoError(t, err)

	assert.Len(t, rp.PeerList, 1)

	pl1 := rp.PeerList[0]
	assert.Equal(t, "1.2.3.4", pl1.Host)
	assert.Equal(t, uint16(9678), pl1.Port)
	assert.Equal(t, uint64(1643913969), pl1.Timestamp)

	// Test going the other direction
	reencodedBytes, err := streamable.Marshal(rp)
	assert.NoError(t, err)
	assert.Equal(t, encodedBytes, reencodedBytes)
}
