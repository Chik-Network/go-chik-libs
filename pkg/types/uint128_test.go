// Original Source: https://github.com/lukechampine/uint128
// Original License:
//
//The MIT License (MIT)
//
//Copyright (c) 2019 Luke Champine
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//THE SOFTWARE.

package types_test

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/chik-network/go-chik-libs/pkg/types"
)

func randUint128(t *testing.T) types.Uint128 {
	randBuf := make([]byte, 16)
	_, err := rand.Read(randBuf)
	if err != nil {
		t.Fatal("Error reading random data")
	}
	return types.Uint128FromBytes(randBuf)
}

func TestUint128(t *testing.T) {
	// test non-arithmetic methods
	for i := 0; i < 1000; i++ {
		x, y := randUint128(t), randUint128(t)
		if i%3 == 0 {
			x = x.Rsh(64)
		} else if i%7 == 0 {
			x = x.Lsh(64)
		}

		if types.Uint128FromBig(x.Big()) != x {
			t.Fatal("FromBig is not the inverse of Big for", x)
		}

		b := make([]byte, 16)
		x.PutBytes(b)
		if types.Uint128FromBytes(b) != x {
			t.Fatal("FromBytes is not the inverse of PutBytes for", x)
		}

		if !x.Equals(x) {
			t.Fatalf("%v does not equal itself", x.Lo)
		}
		if !types.Uint128From64(x.Lo).Equals64(x.Lo) {
			t.Fatalf("%v does not equal itself", x.Lo)
		}

		if x.Cmp(y) != x.Big().Cmp(y.Big()) {
			t.Fatalf("mismatch: cmp(%v,%v) should equal %v, got %v", x, y, x.Big().Cmp(y.Big()), x.Cmp(y))
		} else if x.Cmp(x) != 0 {
			t.Fatalf("%v does not equal itself", x)
		}

		if x.Cmp64(y.Lo) != x.Big().Cmp(types.Uint128From64(y.Lo).Big()) {
			t.Fatalf("mismatch: cmp64(%v,%v) should equal %v, got %v", x, y.Lo, x.Big().Cmp(types.Uint128From64(y.Lo).Big()), x.Cmp64(y.Lo))
		} else if types.Uint128From64(x.Lo).Cmp64(x.Lo) != 0 {
			t.Fatalf("%v does not equal itself", x.Lo)
		}
	}

	// Check FromBig panics
	checkPanic := func(fn func(), msg string) {
		defer func() {
			r := recover()
			if s, ok := r.(string); !ok || s != msg {
				t.Errorf("expected %q, got %q", msg, r)
			}
		}()
		fn()
	}
	checkPanic(func() { _ = types.Uint128FromBig(big.NewInt(-1)) }, "value cannot be negative")
	checkPanic(func() { _ = types.Uint128FromBig(new(big.Int).Lsh(big.NewInt(1), 129)) }, "value overflows Uint128")
}

func TestArithmetic(t *testing.T) {
	// compare Uint128 arithmetic methods to their math/big equivalents, using
	// random values
	randBuf := make([]byte, 17)
	randUint128 := func() types.Uint128 {
		_, err := rand.Read(randBuf)
		if err != nil {
			t.Fatal("Error reading random data")
		}
		var Lo, Hi uint64
		if randBuf[16]&1 != 0 {
			Lo = binary.LittleEndian.Uint64(randBuf[:8])
		}
		if randBuf[16]&2 != 0 {
			Hi = binary.LittleEndian.Uint64(randBuf[8:])
		}
		return types.NewUint128(Lo, Hi)
	}
	mod128 := func(i *big.Int) *big.Int {
		// wraparound semantics
		if i.Sign() == -1 {
			i = i.Add(new(big.Int).Lsh(big.NewInt(1), 128), i)
		}
		_, rem := i.QuoRem(i, new(big.Int).Lsh(big.NewInt(1), 128), new(big.Int))
		return rem
	}
	checkBinOpX := func(x types.Uint128, op string, y types.Uint128, fn func(x, y types.Uint128) types.Uint128, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		rb := fnb(new(big.Int), x.Big(), y.Big())
		defer func() {
			if r := recover(); r != nil {
				if rb.BitLen() <= 128 && rb.Sign() >= 0 {
					t.Fatalf("mismatch: %v%v%v should not panic, %v", x, op, y, rb)
				}
			} else if rb.BitLen() > 128 || rb.Sign() < 0 {
				t.Fatalf("mismatch: %v%v%v should panic, %v", x, op, y, rb)
			}
		}()
		r := fn(x, y)
		if r.Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	checkBinOp := func(x types.Uint128, op string, y types.Uint128, fn func(x, y types.Uint128) types.Uint128, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		r := fn(x, y)
		rb := mod128(fnb(new(big.Int), x.Big(), y.Big()))
		if r.Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	checkShiftOp := func(x types.Uint128, op string, n uint, fn func(x types.Uint128, n uint) types.Uint128, fnb func(z, x *big.Int, n uint) *big.Int) {
		t.Helper()
		r := fn(x, n)
		rb := mod128(fnb(new(big.Int), x.Big(), n))
		if r.Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, n, rb, r)
		}
	}
	checkBinOp64X := func(x types.Uint128, op string, y uint64, fn func(x types.Uint128, y uint64) types.Uint128, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		xb, yb := x.Big(), types.Uint128From64(y).Big()
		rb := fnb(new(big.Int), xb, yb)
		defer func() {
			if r := recover(); r != nil {
				if rb.BitLen() <= 128 && rb.Sign() >= 0 {
					t.Fatalf("mismatch: %v%v%v should not panic, %v", x, op, y, rb)
				}
			} else if rb.BitLen() > 128 || rb.Sign() < 0 {
				t.Fatalf("mismatch: %v%v%v should panic, %v", x, op, y, rb)
			}
		}()
		r := fn(x, y)
		if r.Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	checkBinOp64 := func(x types.Uint128, op string, y uint64, fn func(x types.Uint128, y uint64) types.Uint128, fnb func(z, x, y *big.Int) *big.Int) {
		t.Helper()
		xb, yb := x.Big(), types.Uint128From64(y).Big()
		r := fn(x, y)
		rb := mod128(fnb(new(big.Int), xb, yb))
		if r.Big().Cmp(rb) != 0 {
			t.Fatalf("mismatch: %v%v%v should equal %v, got %v", x, op, y, rb, r)
		}
	}
	for i := 0; i < 1000; i++ {
		x, y, z := randUint128(), randUint128(), uint(randUint128().Lo&0xFF)
		checkBinOpX(x, "[+]", y, types.Uint128.Add, (*big.Int).Add)
		checkBinOpX(x, "[-]", y, types.Uint128.Sub, (*big.Int).Sub)
		checkBinOpX(x, "[*]", y, types.Uint128.Mul, (*big.Int).Mul)
		checkBinOp(x, "+", y, types.Uint128.AddWrap, (*big.Int).Add)
		checkBinOp(x, "-", y, types.Uint128.SubWrap, (*big.Int).Sub)
		checkBinOp(x, "*", y, types.Uint128.MulWrap, (*big.Int).Mul)
		if !y.IsZero() {
			checkBinOp(x, "/", y, types.Uint128.Div, (*big.Int).Div)
			checkBinOp(x, "%", y, types.Uint128.Mod, (*big.Int).Mod)
		}
		checkBinOp(x, "&", y, types.Uint128.And, (*big.Int).And)
		checkBinOp(x, "|", y, types.Uint128.Or, (*big.Int).Or)
		checkBinOp(x, "^", y, types.Uint128.Xor, (*big.Int).Xor)
		checkShiftOp(x, "<<", z, types.Uint128.Lsh, (*big.Int).Lsh)
		checkShiftOp(x, ">>", z, types.Uint128.Rsh, (*big.Int).Rsh)

		// check 64-bit variants
		y64 := y.Lo
		checkBinOp64X(x, "[+]", y64, types.Uint128.Add64, (*big.Int).Add)
		checkBinOp64X(x, "[-]", y64, types.Uint128.Sub64, (*big.Int).Sub)
		checkBinOp64X(x, "[*]", y64, types.Uint128.Mul64, (*big.Int).Mul)
		checkBinOp64(x, "+", y64, types.Uint128.AddWrap64, (*big.Int).Add)
		checkBinOp64(x, "-", y64, types.Uint128.SubWrap64, (*big.Int).Sub)
		checkBinOp64(x, "*", y64, types.Uint128.MulWrap64, (*big.Int).Mul)
		if y64 != 0 {
			checkBinOp64(x, "/", y64, types.Uint128.Div64, (*big.Int).Div)
			modfn := func(x types.Uint128, y uint64) types.Uint128 {
				return types.Uint128From64(x.Mod64(y))
			}
			checkBinOp64(x, "%", y64, modfn, (*big.Int).Mod)
		}
		checkBinOp64(x, "&", y64, types.Uint128.And64, (*big.Int).And)
		checkBinOp64(x, "|", y64, types.Uint128.Or64, (*big.Int).Or)
		checkBinOp64(x, "^", y64, types.Uint128.Xor64, (*big.Int).Xor)
	}
}

func TestOverflowAndUnderflow(t *testing.T) {
	x := types.Uint128Max
	y := types.NewUint128(10, 10)
	z := types.Uint128From64(10)
	checkPanic := func(fn func(), msg string) {
		defer func() {
			r := recover()
			if s, ok := r.(string); !ok || s != msg {
				t.Errorf("expected %q, got %q", msg, r)
			}
		}()
		fn()
	}

	// should panic
	checkPanic(func() { _ = x.Add(y) }, "overflow")
	checkPanic(func() { _ = x.Add64(10) }, "overflow")
	checkPanic(func() { _ = y.Sub(x) }, "underflow")
	checkPanic(func() { _ = z.Sub64(math.MaxInt64) }, "underflow")
	checkPanic(func() { _ = x.Mul(y) }, "overflow")
	checkPanic(func() { _ = types.NewUint128(0, 10).Mul(types.NewUint128(0, 10)) }, "overflow")
	checkPanic(func() { _ = types.NewUint128(0, 1).Mul(types.NewUint128(0, 1)) }, "overflow")
	checkPanic(func() { _ = x.Mul64(math.MaxInt64) }, "overflow")
}

func TestLeadingZeros(t *testing.T) {
	tcs := []struct {
		l     types.Uint128
		r     types.Uint128
		zeros int
	}{
		{
			l:     types.NewUint128(0x00, 0xf000000000000000),
			r:     types.NewUint128(0x00, 0x8000000000000000),
			zeros: 1,
		},
		{
			l:     types.NewUint128(0x00, 0xf000000000000000),
			r:     types.NewUint128(0x00, 0xc000000000000000),
			zeros: 2,
		},
		{
			l:     types.NewUint128(0x00, 0xf000000000000000),
			r:     types.NewUint128(0x00, 0xe000000000000000),
			zeros: 3,
		},
		{
			l:     types.NewUint128(0x00, 0xffff000000000000),
			r:     types.NewUint128(0x00, 0xff00000000000000),
			zeros: 8,
		},
		{
			l:     types.NewUint128(0x00, 0x000000000000ffff),
			r:     types.NewUint128(0x00, 0x000000000000ff00),
			zeros: 56,
		},
		{
			l:     types.NewUint128(0xf000000000000000, 0x01),
			r:     types.NewUint128(0x4000000000000000, 0x00),
			zeros: 63,
		},
		{
			l:     types.NewUint128(0xf000000000000000, 0x00),
			r:     types.NewUint128(0x4000000000000000, 0x00),
			zeros: 64,
		},
		{
			l:     types.NewUint128(0xf000000000000000, 0x00),
			r:     types.NewUint128(0x8000000000000000, 0x00),
			zeros: 65,
		},
		{
			l:     types.NewUint128(0x00, 0x00),
			r:     types.NewUint128(0x00, 0x00),
			zeros: 128,
		},
		{
			l:     types.NewUint128(0x01, 0x00),
			r:     types.NewUint128(0x00, 0x00),
			zeros: 127,
		},
	}

	for _, tc := range tcs {
		zeros := tc.l.Xor(tc.r).LeadingZeros()
		if zeros != tc.zeros {
			t.Errorf("mismatch (expected: %d, got: %d)", tc.zeros, zeros)
		}
	}
}

func TestString(t *testing.T) {
	for i := 0; i < 1000; i++ {
		x := randUint128(t)
		if x.String() != x.Big().String() {
			t.Fatalf("mismatch:\n%v !=\n%v", x.String(), x.Big().String())
		}
	}
	// Test 0 string
	if types.Uint128Zero.String() != "0" {
		t.Fatalf(`Zero.String() should be "0", got %q`, types.Uint128Zero.String())
	}
	// Test Max string
	if types.Uint128Max.String() != "340282366920938463463374607431768211455" {
		t.Fatalf(`Max.String() should be "0", got %q`, types.Uint128Max.String())
	}
}

func BenchmarkArithmetic(b *testing.B) {
	randBuf := make([]byte, 17)
	randUint128 := func() types.Uint128 {
		_, err := rand.Read(randBuf)
		if err != nil {
			b.Fatal("Error reading random data")
		}
		var Lo, Hi uint64
		if randBuf[16]&1 != 0 {
			Lo = binary.LittleEndian.Uint64(randBuf[:8])
		}
		if randBuf[16]&2 != 0 {
			Hi = binary.LittleEndian.Uint64(randBuf[8:])
		}
		return types.NewUint128(Lo, Hi)
	}
	x, y := randUint128(), randUint128()

	b.Run("Add native", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = x.Lo * y.Lo
		}
	})

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x.Add(y)
		}
	})

	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x.Sub(y)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x.Mul(y)
		}
	})

	b.Run("Lsh", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x.Lsh(17)
		}
	})

	b.Run("Rsh", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x.Rsh(17)
		}
	})

	b.Run("Cmp64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x.Cmp64(y.Lo)
		}
	})
}

func BenchmarkDivision(b *testing.B) {
	randBuf := make([]byte, 8)
	randU64 := func() uint64 {
		_, err := rand.Read(randBuf)
		if err != nil {
			b.Fatal("Error reading random data")
		}
		return binary.LittleEndian.Uint64(randBuf) | 3 // avoid divide-by-zero
	}
	x64 := types.Uint128From64(randU64())
	y64 := types.Uint128From64(randU64())
	x128 := types.NewUint128(randU64(), randU64())
	y128 := types.NewUint128(randU64(), randU64())

	b.Run("native 64/64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = x64.Lo / y64.Lo
		}
	})
	b.Run("Div64 64/64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x64.Div64(y64.Lo)
		}
	})
	b.Run("Div64 128/64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x128.Div64(y64.Lo)
		}
	})
	b.Run("Div 64/64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x64.Div(y64)
		}
	})
	b.Run("Div 128/64-Lo", func(b *testing.B) {
		x := x128
		x.Hi = y64.Lo - 1
		for i := 0; i < b.N; i++ {
			x.Div(y64)
		}
	})
	b.Run("Div 128/64-Hi", func(b *testing.B) {
		x := x128
		x.Hi = y64.Lo + 1
		for i := 0; i < b.N; i++ {
			x.Div(y64)
		}
	})
	b.Run("Div 128/128", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x128.Div(y128)
		}
	})
	b.Run("big.Int 128/64", func(b *testing.B) {
		xb, yb := x128.Big(), y64.Big()
		q := new(big.Int)
		for i := 0; i < b.N; i++ {
			q = q.Div(xb, yb)
		}
	})
	b.Run("big.Int 128/128", func(b *testing.B) {
		xb, yb := x128.Big(), y128.Big()
		q := new(big.Int)
		for i := 0; i < b.N; i++ {
			q = q.Div(xb, yb)
		}
	})
}

func BenchmarkString(b *testing.B) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		b.Fatal("Error reading random data")
	}
	x := types.NewUint128(
		binary.LittleEndian.Uint64(buf[:8]),
		binary.LittleEndian.Uint64(buf[8:]),
	)
	xb := x.Big()
	b.Run("Uint128", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = x.String()
		}
	})
	b.Run("big.Int", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = xb.String()
		}
	})
}

func TestUint128_UnmarshalJSON(t *testing.T) {
	jsondata := []byte(`{"int128":18446744073709551616}`)
	structDef := &struct {
		Int128 types.Uint128 `json:"int128"`
	}{}
	err := json.Unmarshal(jsondata, structDef)
	if err != nil {
		t.Error(err)
	}
	if structDef.Int128.String() != "18446744073709551616" {
		t.Error("value did not parse correctly")
	}
}

func TestUint128_UnmarshalJSON_Null(t *testing.T) {
	jsondata := []byte(`{"int128":null}`)
	structDef := &struct {
		Int128 types.Uint128 `json:"int128"`
	}{}
	err := json.Unmarshal(jsondata, structDef)
	if err != nil {
		t.Error(err)
	}
	if structDef.Int128.String() != "0" {
		t.Error("`null` did not unmarshal as zero")
	}
}

func TestUint128_UnmarshalYAML(t *testing.T) {
	yamldata := []byte(`int128: 18446744073709551616`)
	structDef := &struct {
		Int128 types.Uint128 `yaml:"int128"`
	}{}
	err := yaml.Unmarshal(yamldata, structDef)
	if err != nil {
		t.Error(err)
	}
	if structDef.Int128.String() != "18446744073709551616" {
		t.Error("value did not parse correctly")
	}
}

func TestUint128_UnmarshalYAML_Null(t *testing.T) {
	yamldata := []byte(`int128: null`)
	structDef := &struct {
		Int128 types.Uint128 `yaml:"int128"`
	}{}
	err := yaml.Unmarshal(yamldata, structDef)
	if err != nil {
		t.Error(err)
	}
	if structDef.Int128.String() != "0" {
		t.Error("`null` did not unmarshal as zero")
	}
}

func TestNewUint128_MarshalJSON(t *testing.T) {
	num := types.Uint128From64(12345)
	out, err := json.Marshal(num)
	assert.NoError(t, err)
	assert.Equal(t, "12345", string(out))

	bigInt := new(big.Int)
	bigInt.SetString("18446744073709551616", 10)
	num = types.Uint128FromBig(bigInt)
	out, err = json.Marshal(num)
	assert.NoError(t, err)
	assert.Equal(t, "18446744073709551616", string(out))
}

func TestNewUint128_MarshalYAML(t *testing.T) {
	num := types.Uint128From64(12345)
	out, err := yaml.Marshal(num)
	assert.NoError(t, err)
	assert.Equal(t, "12345\n", string(out))

	bigInt := new(big.Int)
	bigInt.SetString("18446744073709551616", 10)
	num = types.Uint128FromBig(bigInt)
	out, err = yaml.Marshal(num)
	assert.NoError(t, err)
	assert.Equal(t, "18446744073709551616\n", string(out))
}
