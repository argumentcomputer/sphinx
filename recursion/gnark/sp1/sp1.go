package sp1

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear"
	"github.com/succinctlabs/sp1-recursion-gnark/poseidon2"
)

type Circuit struct {
	Vars                 []frontend.Variable
	Felts                []*babybear.Variable
	Exts                 []*babybear.ExtensionVariable
	VkeyHash             frontend.Variable `gnark:",public"`
	CommitedValuesDigest frontend.Variable `gnark:",public"`
}

type Constraint struct {
	Opcode string     `json:"opcode"`
	Args   [][]string `json:"args"`
}

type WitnessInput struct {
	Vars                 []string   `json:"vars"`
	Felts                []string   `json:"felts"`
	Exts                 [][]string `json:"exts"`
	VkeyHash             string     `json:"vkey_hash"`
	CommitedValuesDigest string     `json:"commited_values_digest"`
}

type Groth16Proof struct {
	A            [2]string    `json:"a"`
	B            [2][2]string `json:"b"`
	C            [2]string    `json:"c"`
	PublicInputs [2]string    `json:"public_inputs"`
}

type PlonkBn254Proof struct {
	Proof        string    `json:"proof"`
	PublicInputs [2]string `json:"public_inputs"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// Get the file name from an environment variable.
	fileName := os.Getenv("CONSTRAINTS_JSON")
	if fileName == "" {
		fileName = "constraints.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Deserialize the JSON data into a slice of Instruction structs.
	var constraints []Constraint
	err = json.Unmarshal(data, &constraints)
	if err != nil {
		return fmt.Errorf("error deserializing JSON: %v", err)
	}

	hashAPI := poseidon2.NewChip(api)
	fieldAPI := babybear.NewChip(api)
	vars := make(map[string]frontend.Variable)
	felts := make(map[string]*babybear.Variable)
	exts := make(map[string]*babybear.ExtensionVariable)

	// Iterate through the instructions and handle each opcode.
	for _, cs := range constraints {
		switch cs.Opcode {
		case "ImmV":
			vars[cs.Args[0][0]] = frontend.Variable(cs.Args[1][0])
		case "ImmF":
			felts[cs.Args[0][0]] = babybear.NewF(cs.Args[1][0])
		case "ImmE":
			exts[cs.Args[0][0]] = babybear.NewE(cs.Args[1])
		case "AddV":
			vars[cs.Args[0][0]] = api.Add(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "AddF":
			felts[cs.Args[0][0]] = fieldAPI.AddF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "AddE":
			exts[cs.Args[0][0]] = fieldAPI.AddE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "AddEF":
			exts[cs.Args[0][0]] = fieldAPI.AddEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubV":
			vars[cs.Args[0][0]] = api.Sub(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "SubF":
			felts[cs.Args[0][0]] = fieldAPI.SubF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubE":
			exts[cs.Args[0][0]] = fieldAPI.SubE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "MulV":
			vars[cs.Args[0][0]] = api.Mul(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "MulF":
			felts[cs.Args[0][0]] = fieldAPI.MulF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulE":
			exts[cs.Args[0][0]] = fieldAPI.MulE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "DivE":
			exts[cs.Args[0][0]] = fieldAPI.DivE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "NegE":
			exts[cs.Args[0][0]] = fieldAPI.NegE(exts[cs.Args[1][0]])
		case "InvE":
			exts[cs.Args[0][0]] = fieldAPI.InvE(exts[cs.Args[1][0]])
		case "Num2BitsV":
			numBits, err := strconv.Atoi(cs.Args[2][0])
			if err != nil {
				return fmt.Errorf("error converting number of bits to int: %v", err)
			}
			bits := api.ToBinary(vars[cs.Args[1][0]], numBits)
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Num2BitsF":
			bits := fieldAPI.ToBinary(felts[cs.Args[1][0]])
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Permute":
			state := [3]frontend.Variable{vars[cs.Args[0][0]], vars[cs.Args[1][0]], vars[cs.Args[2][0]]}
			hashAPI.PermuteMut(&state)
			vars[cs.Args[0][0]] = state[0]
			vars[cs.Args[1][0]] = state[1]
			vars[cs.Args[2][0]] = state[2]
		case "SelectV":
			vars[cs.Args[0][0]] = api.Select(vars[cs.Args[1][0]], vars[cs.Args[2][0]], vars[cs.Args[3][0]])
		case "SelectF":
			felts[cs.Args[0][0]] = fieldAPI.SelectF(vars[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]])
		case "SelectE":
			exts[cs.Args[0][0]] = fieldAPI.SelectE(vars[cs.Args[1][0]], exts[cs.Args[2][0]], exts[cs.Args[3][0]])
		case "Ext2Felt":
			out := fieldAPI.Ext2Felt(exts[cs.Args[4][0]])
			for i := 0; i < 4; i++ {
				felts[cs.Args[i][0]] = out[i]
			}
		case "AssertEqV":
			api.AssertIsEqual(vars[cs.Args[0][0]], vars[cs.Args[1][0]])
		case "AssertEqF":
			fieldAPI.AssertIsEqualV(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertEqE":
			fieldAPI.AssertIsEqualE(exts[cs.Args[0][0]], exts[cs.Args[1][0]])
		case "PrintV":
			api.Println(vars[cs.Args[0][0]])
		case "PrintF":
			fieldAPI.PrintF(felts[cs.Args[0][0]])
		case "PrintE":
			fieldAPI.PrintE(exts[cs.Args[0][0]])
		case "WitnessV":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			vars[cs.Args[0][0]] = circuit.Vars[i]
		case "WitnessF":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			felts[cs.Args[0][0]] = circuit.Felts[i]
		case "WitnessE":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			exts[cs.Args[0][0]] = circuit.Exts[i]
		case "CommitVkeyHash":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.VkeyHash, element)
		case "CommitCommitedValuesDigest":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.CommitedValuesDigest, element)
		default:
			return fmt.Errorf("unhandled opcode: %s", cs.Opcode)
		}
	}

	return nil
}
