package bech32m_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chik-network/go-chik-libs/pkg/bech32m"
	"github.com/chik-network/go-chik-libs/pkg/types"
)

func TestKnownAddressConversions(t *testing.T) {
	// Address: Hexstr
	combinations := map[string]map[string]string{
		"xck": {
			"xck1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm6ksjy75z0": "000000000000000000000000000000000000000000000000000000000000dead",
			"xck1arjpkq2a5kjd7t2st93wxqd0axcnfpq04xzyjespkr0xxakslcvqenhpru": "e8e41b015da5a4df2d505962e301afe9b134840fa984496601b0de6376d0fe18", // Random Keys
		},
		"txck": {
			"txck1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm6kslrezru": "000000000000000000000000000000000000000000000000000000000000dead",
			"txck1arjpkq2a5kjd7t2st93wxqd0axcnfpq04xzyjespkr0xxakslcvq55shz0": "e8e41b015da5a4df2d505962e301afe9b134840fa984496601b0de6376d0fe18", // Random Keys
		},
	}

	for prefix, tests := range combinations {
		for address, hexstr := range tests {
			t.Run(address, func(t *testing.T) {
				hexbytes, err := hex.DecodeString(hexstr)
				assert.NoError(t, err)
				hexbytes32, err := types.BytesToBytes32(hexbytes)
				assert.NoError(t, err)

				// Test encoding
				generatedAddress, err := bech32m.EncodePuzzleHash(hexbytes32, prefix)
				assert.NoError(t, err)
				assert.Equal(t, address, generatedAddress)

				// Test decoding
				_, generatedBytes, err := bech32m.DecodePuzzleHash(address)
				assert.NoError(t, err)
				assert.Equal(t, hexbytes32, generatedBytes)
			})

		}
	}
}
