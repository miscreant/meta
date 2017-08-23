package block

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type dblExample struct {
	input  []byte
	output []byte
}

// Load dbl test vectors from dbl.tjson
// TODO: switch to a native Go TJSON parser when available
func loadDblExamples() []dblExample {
	var examplesJSON map[string]interface{}

	exampleData, err := ioutil.ReadFile("../../vectors/dbl.tjson")
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(exampleData, &examplesJSON); err != nil {
		panic(err)
	}

	examplesArray := examplesJSON["examples:A<O>"].([]interface{})

	if examplesArray == nil {
		panic("no toplevel 'examples:A<O>' key in dbl.tjson")
	}

	result := make([]dblExample, len(examplesArray))

	for i, exampleJSON := range examplesArray {
		example := exampleJSON.(map[string]interface{})

		inputHex := example["input:d16"].(string)
		input := make([]byte, hex.DecodedLen(len(inputHex)))

		if _, err := hex.Decode(input, []byte(inputHex)); err != nil {
			panic(err)
		}

		outputHex := example["output:d16"].(string)
		output := make([]byte, hex.DecodedLen(len(outputHex)))

		if _, err := hex.Decode(output, []byte(outputHex)); err != nil {
			panic(err)
		}

		result[i] = dblExample{input, output}
	}

	return result
}

func TestDbl(t *testing.T) {
	for i, tt := range loadDblExamples() {
		var b Block
		copy(b[:], tt.input)
		b.Dbl()

		if !bytes.Equal(b[:], tt.output) {
			t.Errorf("test %d: dbl mismatch\n\twant %x\n\thave %x", i, tt.output, b)
			continue
		}
	}
}
