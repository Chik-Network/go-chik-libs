package types_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/chik-network/go-chik-libs/pkg/types"
)

func TestTimestamp_MarshalJSON(t *testing.T) {
	ts := types.Timestamp{Time: time.Unix(1668052345, 0)}
	expected := `1668052345`
	marshalled, err := json.Marshal(ts)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(marshalled))
}

func TestTimestamp_UnmarshalJSON(t *testing.T) {
	data := []byte(`1668052345`)
	expected := types.Timestamp{Time: time.Unix(1668052345, 0)}
	unmarshalled := &types.Timestamp{}
	err := json.Unmarshal(data, unmarshalled)
	assert.NoError(t, err)
	assert.Equal(t, expected, *unmarshalled)
}

func TestTimestamp_UnmarshalJSONFloat(t *testing.T) {
	data := []byte(`1668050986.646834`)
	expected := types.Timestamp{Time: time.Unix(1668050986, 0)}
	unmarshalled := &types.Timestamp{}
	err := json.Unmarshal(data, unmarshalled)
	assert.NoError(t, err)
	assert.Equal(t, expected, *unmarshalled)
}
