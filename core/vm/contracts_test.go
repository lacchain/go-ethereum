// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// precompiledTest defines the input/output pairs for precompiled contract tests.
type precompiledTest struct {
	Input, Expected string
	Gas             uint64
	Name            string
	NoBenchmark     bool // Benchmark primarily the worst-cases
}

// precompiledFailureTest defines the input/error pairs for precompiled
// contract failure tests.
type precompiledFailureTest struct {
	Input         string
	ExpectedError string
	Name          string
}

// allPrecompiles does not map to the actual set of precompiles, as it also contains
// repriced versions of precompiles at certain slots
var allPrecompiles = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):    &ecrecover{},
	common.BytesToAddress([]byte{2}):    &sha256hash{},
	common.BytesToAddress([]byte{3}):    &ripemd160hash{},
	common.BytesToAddress([]byte{4}):    &dataCopy{},
	common.BytesToAddress([]byte{5}):    &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{0xf5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):    &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):    &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):    &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):    &blake2F{},
	common.BytesToAddress([]byte{10}):   &bls12381G1Add{},
	common.BytesToAddress([]byte{11}):   &bls12381G1Mul{},
	common.BytesToAddress([]byte{12}):   &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{13}):   &bls12381G2Add{},
	common.BytesToAddress([]byte{14}):   &bls12381G2Mul{},
	common.BytesToAddress([]byte{15}):   &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{16}):   &bls12381Pairing{},
	common.BytesToAddress([]byte{17}):   &bls12381MapG1{},
	common.BytesToAddress([]byte{18}):   &bls12381MapG2{},
	common.BytesToAddress([]byte{20}):   &kzgPointEvaluation{},
	common.BytesToAddress([]byte{19}):   &falcon512{},
}

// EIP-152 test vectors
var blake2FMalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 0: empty input",
	},
	{
		Input:         "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 1: less than 213 bytes input",
	},
	{
		Input:         "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 2: more than 213 bytes input",
	},
	{
		Input:         "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002",
		ExpectedError: errBlake2FInvalidFinalFlag.Error(),
		Name:          "vector 3: malformed final block indicator flag",
	},
}

// EIP-7213 test vectors
var falcon512MalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: errFalcon512InvalidInput.Error(),
		Name:          "vector 0: empty input",
	},
	{
		Input:         "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000003103d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab04202",
		ExpectedError: errFalcon512InvalidInput.Error(),
		Name:          "vector 1: signature lenght/public key lenght not present in input",
	},
	{
		Input:         "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c03d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab04202000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		ExpectedError: errFalcon512InvalidInput.Error(),
		Name:          "vector 2: Signature indicated length is zero",
	},
	{
		Input:         "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c03d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab04202000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		ExpectedError: errFalcon512InvalidInput.Error(),
		Name:          "vector 3: Public Key indicated length is zero",
	},
	{
		Input:         "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c03d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab04202000000000000000000000000000000000000000000000000000000000007774000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		ExpectedError: errFalcon512InvalidInput.Error(),
		Name:          "vector 4: Signature indicated length is too long",
	},
	{
		Input:         "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c03d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab04202000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004444000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		ExpectedError: errFalcon512InvalidInput.Error(),
		Name:          "vector 5: Public Key indicated length is too long",
	},
}

func testPrecompiled(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		if res, _, err := RunPrecompiledContract(p, in, gas); err != nil {
			t.Error(err)
		} else if common.Bytes2Hex(res) != test.Expected {
			t.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
		}
		if expGas := test.Gas; expGas != gas {
			t.Errorf("%v: gas wrong, expected %d, got %d", test.Name, expGas, gas)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledOOG(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in) - 1

	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, in, gas)
		if err.Error() != "out of gas" {
			t.Errorf("Expected error [out of gas], got [%v]", err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledFailure(addr string, test precompiledFailureTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(test.Name, func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, in, gas)
		if err.Error() != test.ExpectedError {
			t.Errorf("Expected error [%v], got [%v]", test.ExpectedError, err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func benchmarkPrecompiled(addr string, test precompiledTest, bench *testing.B) {
	if test.NoBenchmark {
		return
	}
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	reqGas := p.RequiredGas(in)

	var (
		res  []byte
		err  error
		data = make([]byte, len(in))
	)

	bench.Run(fmt.Sprintf("%s-Gas=%d", test.Name, reqGas), func(bench *testing.B) {
		bench.ReportAllocs()
		start := time.Now()
		bench.ResetTimer()
		for i := 0; i < bench.N; i++ {
			copy(data, in)
			res, _, err = RunPrecompiledContract(p, data, reqGas)
		}
		bench.StopTimer()
		elapsed := uint64(time.Since(start))
		if elapsed < 1 {
			elapsed = 1
		}
		gasUsed := reqGas * uint64(bench.N)
		bench.ReportMetric(float64(reqGas), "gas/op")
		// Keep it as uint64, multiply 100 to get two digit float later
		mgasps := (100 * 1000 * gasUsed) / elapsed
		bench.ReportMetric(float64(mgasps)/100, "mgas/s")
		//Check if it is correct
		if err != nil {
			bench.Error(err)
			return
		}
		if common.Bytes2Hex(res) != test.Expected {
			bench.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
			return
		}
	})
}

// Benchmarks the sample inputs from the ECRECOVER precompile.
func BenchmarkPrecompiledEcrecover(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "000000000000000000000000ceaccac640adf55b2028469bd36ba501f28b699d",
		Name:     "",
	}
	benchmarkPrecompiled("01", t, bench)
}

// Benchmarks the sample inputs from the SHA256 precompile.
func BenchmarkPrecompiledSha256(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "811c7003375852fabd0d362e40e68607a12bdabae61a7d068fe5fdd1dbbf2a5d",
		Name:     "128",
	}
	benchmarkPrecompiled("02", t, bench)
}

// Benchmarks the sample inputs from the RIPEMD precompile.
func BenchmarkPrecompiledRipeMD(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "0000000000000000000000009215b8d9882ff46f0dfde6684d78e831467f65e6",
		Name:     "128",
	}
	benchmarkPrecompiled("03", t, bench)
}

// Benchmarks the sample inputs from the identiy precompile.
func BenchmarkPrecompiledIdentity(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Name:     "128",
	}
	benchmarkPrecompiled("04", t, bench)
}

// Tests the sample inputs from the ModExp EIP 198.
func TestPrecompiledModExp(t *testing.T)      { testJson("modexp", "05", t) }
func BenchmarkPrecompiledModExp(b *testing.B) { benchJson("modexp", "05", b) }

func TestPrecompiledModExpEip2565(t *testing.T)      { testJson("modexp_eip2565", "f5", t) }
func BenchmarkPrecompiledModExpEip2565(b *testing.B) { benchJson("modexp_eip2565", "f5", b) }

// Tests the sample inputs from the elliptic curve addition EIP 213.
func TestPrecompiledBn256Add(t *testing.T)      { testJson("bn256Add", "06", t) }
func BenchmarkPrecompiledBn256Add(b *testing.B) { benchJson("bn256Add", "06", b) }

// Tests OOG
func TestPrecompiledModExpOOG(t *testing.T) {
	modexpTests, err := loadJson("modexp")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range modexpTests {
		testPrecompiledOOG("05", test, t)
	}
}

// Tests the sample inputs from the elliptic curve scalar multiplication EIP 213.
func TestPrecompiledBn256ScalarMul(t *testing.T)      { testJson("bn256ScalarMul", "07", t) }
func BenchmarkPrecompiledBn256ScalarMul(b *testing.B) { benchJson("bn256ScalarMul", "07", b) }

// Tests the sample inputs from the elliptic curve pairing check EIP 197.
func TestPrecompiledBn256Pairing(t *testing.T)      { testJson("bn256Pairing", "08", t) }
func BenchmarkPrecompiledBn256Pairing(b *testing.B) { benchJson("bn256Pairing", "08", b) }

func TestPrecompiledBlake2F(t *testing.T)      { testJson("blake2F", "09", t) }
func BenchmarkPrecompiledBlake2F(b *testing.B) { benchJson("blake2F", "09", b) }

func TestPrecompileBlake2FMalformedInput(t *testing.T) {
	for _, test := range blake2FMalformedInputTests {
		testPrecompiledFailure("09", test, t)
	}
}

func TestPrecompiledEcrecover(t *testing.T) { testJson("ecRecover", "01", t) }

func testJson(name, addr string, t *testing.T) {
	tests, err := loadJson(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiled(addr, test, t)
	}
}

func testJsonFail(name, addr string, t *testing.T) {
	tests, err := loadJsonFail(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiledFailure(addr, test, t)
	}
}

func benchJson(name, addr string, b *testing.B) {
	tests, err := loadJson(name)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range tests {
		benchmarkPrecompiled(addr, test, b)
	}
}

func TestPrecompiledBLS12381G1Add(t *testing.T)      { testJson("blsG1Add", "0a", t) }
func TestPrecompiledBLS12381G1Mul(t *testing.T)      { testJson("blsG1Mul", "0b", t) }
func TestPrecompiledBLS12381G1MultiExp(t *testing.T) { testJson("blsG1MultiExp", "0c", t) }
func TestPrecompiledBLS12381G2Add(t *testing.T)      { testJson("blsG2Add", "0d", t) }
func TestPrecompiledBLS12381G2Mul(t *testing.T)      { testJson("blsG2Mul", "0e", t) }
func TestPrecompiledBLS12381G2MultiExp(t *testing.T) { testJson("blsG2MultiExp", "0f", t) }
func TestPrecompiledBLS12381Pairing(t *testing.T)    { testJson("blsPairing", "10", t) }
func TestPrecompiledBLS12381MapG1(t *testing.T)      { testJson("blsMapG1", "11", t) }
func TestPrecompiledBLS12381MapG2(t *testing.T)      { testJson("blsMapG2", "12", t) }
func TestPrecompiledPointEvaluation(t *testing.T)    { testJson("pointEvaluation", "14", t) }

func BenchmarkPrecompiledBLS12381G1Add(b *testing.B)      { benchJson("blsG1Add", "0a", b) }
func BenchmarkPrecompiledBLS12381G1Mul(b *testing.B)      { benchJson("blsG1Mul", "0b", b) }
func BenchmarkPrecompiledBLS12381G1MultiExp(b *testing.B) { benchJson("blsG1MultiExp", "0c", b) }
func BenchmarkPrecompiledBLS12381G2Add(b *testing.B)      { benchJson("blsG2Add", "0d", b) }
func BenchmarkPrecompiledBLS12381G2Mul(b *testing.B)      { benchJson("blsG2Mul", "0e", b) }
func BenchmarkPrecompiledBLS12381G2MultiExp(b *testing.B) { benchJson("blsG2MultiExp", "0f", b) }
func BenchmarkPrecompiledBLS12381Pairing(b *testing.B)    { benchJson("blsPairing", "10", b) }
func BenchmarkPrecompiledBLS12381MapG1(b *testing.B)      { benchJson("blsMapG1", "11", b) }
func BenchmarkPrecompiledBLS12381MapG2(b *testing.B)      { benchJson("blsMapG2", "12", b) }

// Failure tests
func TestPrecompiledBLS12381G1AddFail(t *testing.T)      { testJsonFail("blsG1Add", "0a", t) }
func TestPrecompiledBLS12381G1MulFail(t *testing.T)      { testJsonFail("blsG1Mul", "0b", t) }
func TestPrecompiledBLS12381G1MultiExpFail(t *testing.T) { testJsonFail("blsG1MultiExp", "0c", t) }
func TestPrecompiledBLS12381G2AddFail(t *testing.T)      { testJsonFail("blsG2Add", "0d", t) }
func TestPrecompiledBLS12381G2MulFail(t *testing.T)      { testJsonFail("blsG2Mul", "0e", t) }
func TestPrecompiledBLS12381G2MultiExpFail(t *testing.T) { testJsonFail("blsG2MultiExp", "0f", t) }
func TestPrecompiledBLS12381PairingFail(t *testing.T)    { testJsonFail("blsPairing", "10", t) }
func TestPrecompiledBLS12381MapG1Fail(t *testing.T)      { testJsonFail("blsMapG1", "11", t) }
func TestPrecompiledBLS12381MapG2Fail(t *testing.T)      { testJsonFail("blsMapG2", "12", t) }

func loadJson(name string) ([]precompiledTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

func loadJsonFail(name string) ([]precompiledFailureTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/fail-%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledFailureTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

// BenchmarkPrecompiledBLS12381G1MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G1MultiExpWorstCase(b *testing.B) {
	task := "0000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be1" +
		"0000000000000000000000000000000011bc8afe71676e6730702a46ef817060249cd06cd82e6981085012ff6d013aa4470ba3a2c71e13ef653e1e223d1ccfe9" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 4787; i++ {
		input = input + task
	}
	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000005a6310ea6f2a598023ae48819afc292b4dfcb40aabad24a0c2cb6c19769465691859eeb2a764342a810c5038d700f18000000000000000000000000000000001268ac944437d15923dc0aec00daa9250252e43e4b35ec7a19d01f0d6cd27f6e139d80dae16ba1c79cc7f57055a93ff5",
		Name:        "WorstCaseG1",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("0c", testcase, b)
}

// BenchmarkPrecompiledBLS12381G2MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G2MultiExpWorstCase(b *testing.B) {
	task := "000000000000000000000000000000000d4f09acd5f362e0a516d4c13c5e2f504d9bd49fdfb6d8b7a7ab35a02c391c8112b03270d5d9eefe9b659dd27601d18f" +
		"000000000000000000000000000000000fd489cb75945f3b5ebb1c0e326d59602934c8f78fe9294a8877e7aeb95de5addde0cb7ab53674df8b2cfbb036b30b99" +
		"00000000000000000000000000000000055dbc4eca768714e098bbe9c71cf54b40f51c26e95808ee79225a87fb6fa1415178db47f02d856fea56a752d185f86b" +
		"000000000000000000000000000000001239b7640f416eb6e921fe47f7501d504fadc190d9cf4e89ae2b717276739a2f4ee9f637c35e23c480df029fd8d247c7" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 1040; i++ {
		input = input + task
	}

	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000018f5ea0c8b086095cfe23f6bb1d90d45de929292006dba8cdedd6d3203af3c6bbfd592e93ecb2b2c81004961fdcbb46c00000000000000000000000000000000076873199175664f1b6493a43c02234f49dc66f077d3007823e0343ad92e30bd7dc209013435ca9f197aca44d88e9dac000000000000000000000000000000000e6f07f4b23b511eac1e2682a0fc224c15d80e122a3e222d00a41fab15eba645a700b9ae84f331ae4ed873678e2e6c9b000000000000000000000000000000000bcb4849e460612aaed79617255fd30c03f51cf03d2ed4163ca810c13e1954b1e8663157b957a601829bb272a4e6c7b8",
		Name:        "WorstCaseG2",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("0f", testcase, b)
}

func BenchmarkPrecompiledFalcon512(bench *testing.B) {
	t := precompiledTest{ // signature: c4d06258 -> verify(bytes,bytes,bytes32)
		Input:    "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000003103d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab0420200000000000000000000000000000000000000000000000000000000000002903933b3c07507e4201748494d832b6ee2a6c93bff9b0ee343b550d1f85a3d0de0d704c6d1784295130960fbe956c6851e141ab3c09a5475bdda2d81ee113f1e16e2ddd8e408bbb3f5b06a555d8f1ac072e5be2f9a365b33ace3d8254709c185b6f3d3db4b50baf14536779f24b5e843fb36b5a00ca475d1801a964d09961c1959dad0f80f0615476c75f58e4ae9a9f8eb93e65f1a4753ca75a62269d74a49ddc75f539bfecd60fe3c8966e77b01d9c69a965a39907862b2de754ad319644d21134fccee194278b326aa4e94359f1d4a08814cad9b27d62687cc31cfcf057490cea0512e02b3b3834e6803c30679f2f2ae2bf4d4e670b283f5105dad272da0f8b95168ea1080b184d98787ba335c22a0a40fd5ba4a70d905c373304c2759e695214f741b98629184789ffdaf63731b43188bda77ed49924da34968ee347b973b525ce0b40af92889b479e5e8717c05c923d76f0bf4689747de1821c1c42968eb164a5fe7c25ef75629511ce220c9d71c4fdb4d60b927b1e473dcda691062b6977338e8666b8c82b8f0f118eefeb5e66e408e63aa9cf876a0a4249688aae132955f5ea98fff2bb4f565b4ec4db39d414dd9c9d3edd089ac74af2f9f3feffa72332982d5e470a74bb2b3b7462639ed89319a327e8a11aef2e3cc391789b4c616b1aef335e9b47a294a47d2c42e7daca30c119e8098b6895aa32bb989a675aa72e84dc1ccc8b9f1a6cd274adbb86fc5ca9c2744cd73f064eba715e06dce542ef0646c94f41d3f47bb7c1a6c4e91ee55996dec4cbbc931f0047e3ba251f71b0bbc7e8633cc7479b1361697a131436d5958ee6fd1ccc1a5d31a9a8391bde2d075cce140de8f1dc58a093310821ae1d26917bc2a17dec09225374ee078d977f901825955ec8623304459a51e5cf7fe60c68b16800000000000000000000000000000000000000000000000000000000000000381096ba86cb658a8f445c9a5e4c28374bec879c8655f68526923240918074d0147c03162e4a49200648c652803c6fd7509ae9aa799d6310d0bd42724e0635920186207000767ca5a8546b1755308c304b84fc93b069e265985b398d6b834698287ff829aa820f17a7f4226ab21f601ebd7175226bab256d8888f009032566d6383d68457ea155a94301870d589c678ed304259e9d37b193bc2a7ccbcbec51d69158c44073aec9792630253318bc954dbf50d15028290dc2d309c7b7b02a6823744d463da17749595cb77e6d16d20d1b4c3aad89d320ebe5a672bb96d6cd5c1efec8b811200cbb062e473352540eddef8af9499f8cdd1dc7c6873f0c7a6bcb7097560271f946849b7f373640bb69ca9b518aa380a6eb0a7275ee84e9c221aed88f5bfbaf43a3ede8e6aa42558104faf800e018441930376c6f6e751569971f47adbca5ca00c801988f317a18722a29298925ea154dbc9024e120524a2d41dc0f18fd8d909f6c50977404e201767078ba9a1f9e40a8b2ba9c01b7da3a0b73a4c2a6b4f518bbee3455d0af2204ddc031c805c72ccb647940b1e6794d859aaebcea0deb581d61b9248bd9697b5cb974a8176e8f910469cae0ab4ed92d2aee9f7eb50296daf8057476305c1189d1d9840a0944f0447fb81e511420e67891b98fa6c257034d5a063437d379177ce8d3fa6eaf12e2dbb7eb8e498481612b1929617da5fb45e4cdf893927d8ba842aa861d9c50471c6d0c6df7e2bb26465a0eb6a3a709de792aafaaf922aa95dd5920b72b4b8856c6e632860b10f5cc08450003671af388961872b466400adb815ba81ea794945d19a100622a6ca0d41c4ea620c21dc125119e372418f04402d9fa7180f7bc89afa54f8082244a42f46e5b5abce87b50a7d6febe8d7bbbac92657cbda1db7c25572a4c1d0baea30447a865a2b1036b880037e2f4d26d453e9e913259779e9169b28a62eb809a5c744e04e260e1f2bbda874f1ac674839ddb47b3148c5946de0180148b7973d63c58193b17cd05d16e80cd7928c2a338363a23a81c0608c87505589b9da1c617e7b70786b6754fbb30a5816810b9e126cfcc5aa49326e9d842973874b6359b5db75610ba68a98c7b5e83f125a82522e13b83fb8f864e2a97b73b5d544a7415b6504a13939eab1595d64faf41fab25a864a574de524405e878339877886d2fc07fa0311508252413edfa1158466667aff78386daf7cb4c9b850992f96e20525330599ab601d454688e294c8c3e",
		Expected: "73aa7ae4db8706ba89cbc14fa6ad475de55d65cb51c2c492ea4b1a1c4f1853e2",
		Name:     "",
	}
	benchmarkPrecompiled("13", t, bench)
}


func TestPrecompileFalcon512MalformedInput(t *testing.T) {
	for _, test := range falcon512MalformedInputTests {
		testPrecompiledFailure("13", test, t)
	}
}

func TestPrecompiledFalcon512InvalidSignature(t *testing.T)  {
	p := allPrecompiles[common.HexToAddress("13")]
	test := precompiledTest{
		Input:    "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000003103d474d06cef2d8da1c97afd7d4993ba792297ca4e161967578494141cab0420200000000000000000000000000000000000000000000000000000000000002901113b3c07507e4201748494d832b6ee2a6c93bff9b0ee343b550d1f85a3d0de0d704c6d1784295130960fbe956c6851e141ab3c09a5475bdda2d81ee113f1e16e2ddd8e408bbb3f5b06a555d8f1ac072e5be2f9a365b33ace3d8254709c185b6f3d3db4b50baf14536779f24b5e843fb36b5a00ca475d1801a964d09961c1959dad0f80f0615476c75f58e4ae9a9f8eb93e65f1a4753ca75a62269d74a49ddc75f539bfecd60fe3c8966e77b01d9c69a965a39907862b2de754ad319644d21134fccee194278b326aa4e94359f1d4a08814cad9b27d62687cc31cfcf057490cea0512e02b3b3834e6803c30679f2f2ae2bf4d4e670b283f5105dad272da0f8b95168ea1080b184d98787ba335c22a0a40fd5ba4a70d905c373304c2759e695214f741b98629184789ffdaf63731b43188bda77ed49924da34968ee347b973b525ce0b40af92889b479e5e8717c05c923d76f0bf4689747de1821c1c42968eb164a5fe7c25ef75629511ce220c9d71c4fdb4d60b927b1e473dcda691062b6977338e8666b8c82b8f0f118eefeb5e66e408e63aa9cf876a0a4249688aae132955f5ea98fff2bb4f565b4ec4db39d414dd9c9d3edd089ac74af2f9f3feffa72332982d5e470a74bb2b3b7462639ed89319a327e8a11aef2e3cc391789b4c616b1aef335e9b47a294a47d2c42e7daca30c119e8098b6895aa32bb989a675aa72e84dc1ccc8b9f1a6cd274adbb86fc5ca9c2744cd73f064eba715e06dce542ef0646c94f41d3f47bb7c1a6c4e91ee55996dec4cbbc931f0047e3ba251f71b0bbc7e8633cc7479b1361697a131436d5958ee6fd1ccc1a5d31a9a8391bde2d075cce140de8f1dc58a093310821ae1d26917bc2a17dec09225374ee078d977f901825955ec8623304459a51e5cf7fe60c68b16800000000000000000000000000000000000000000000000000000000000000381096ba86cb658a8f445c9a5e4c28374bec879c8655f68526923240918074d0147c03162e4a49200648c652803c6fd7509ae9aa799d6310d0bd42724e0635920186207000767ca5a8546b1755308c304b84fc93b069e265985b398d6b834698287ff829aa820f17a7f4226ab21f601ebd7175226bab256d8888f009032566d6383d68457ea155a94301870d589c678ed304259e9d37b193bc2a7ccbcbec51d69158c44073aec9792630253318bc954dbf50d15028290dc2d309c7b7b02a6823744d463da17749595cb77e6d16d20d1b4c3aad89d320ebe5a672bb96d6cd5c1efec8b811200cbb062e473352540eddef8af9499f8cdd1dc7c6873f0c7a6bcb7097560271f946849b7f373640bb69ca9b518aa380a6eb0a7275ee84e9c221aed88f5bfbaf43a3ede8e6aa42558104faf800e018441930376c6f6e751569971f47adbca5ca00c801988f317a18722a29298925ea154dbc9024e120524a2d41dc0f18fd8d909f6c50977404e201767078ba9a1f9e40a8b2ba9c01b7da3a0b73a4c2a6b4f518bbee3455d0af2204ddc031c805c72ccb647940b1e6794d859aaebcea0deb581d61b9248bd9697b5cb974a8176e8f910469cae0ab4ed92d2aee9f7eb50296daf8057476305c1189d1d9840a0944f0447fb81e511420e67891b98fa6c257034d5a063437d379177ce8d3fa6eaf12e2dbb7eb8e498481612b1929617da5fb45e4cdf893927d8ba842aa861d9c50471c6d0c6df7e2bb26465a0eb6a3a709de792aafaaf922aa95dd5920b72b4b8856c6e632860b10f5cc08450003671af388961872b466400adb815ba81ea794945d19a100622a6ca0d41c4ea620c21dc125119e372418f04402d9fa7180f7bc89afa54f8082244a42f46e5b5abce87b50a7d6febe8d7bbbac92657cbda1db7c25572a4c1d0baea30447a865a2b1036b880037e2f4d26d453e9e913259779e9169b28a62eb809a5c744e04e260e1f2bbda874f1ac674839ddb47b3148c5946de0180148b7973d63c58193b17cd05d16e80cd7928c2a338363a23a81c0608c87505589b9da1c617e7b70786b6754fbb30a5816810b9e126cfcc5aa49326e9d842973874b6359b5db75610ba68a98c7b5e83f125a82522e13b83fb8f864e2a97b73b5d544a7415b6504a13939eab1595d64faf41fab25a864a574de524405e878339877886d2fc07fa0311508252413edfa1158466667aff78386daf7cb4c9b850992f96e20525330599ab601d454688e294c8c3e",
		Expected: "0000000000000000000000000000000000000000000000000000000000000000",
		Name:     "Invalid Signature",
	}
	in := common.Hex2Bytes(test.Input)
	reqGas := p.RequiredGas(in)
	test.Gas = reqGas
	testPrecompiled("13", test, t)
}