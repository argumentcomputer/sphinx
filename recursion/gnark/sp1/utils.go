package sp1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear_v2"
)

// Function for serializaton of a gnark groth16 proof to a Solidity-formatted proof.
func SerializeToSolidityRepresentation(proof groth16.Proof, vkeyHash string, commitedValuesDigest string) (SolidityGroth16Proof, error) {
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity")
	}
	proofBytes := _proof.MarshalSolidity()

	// solidity contract inputs
	var publicInputs [2]string

	publicInputs[0] = vkeyHash
	publicInputs[1] = commitedValuesDigest

	return SolidityGroth16Proof{
		PublicInputs:  publicInputs,
		SolidityProof: hex.EncodeToString(proofBytes),
	}, nil
}

// Function to serialize a gnark groth16 proof to a Base-64 encoded Groth16Proof.
func SerializeGnarkGroth16Proof(proof *groth16.Proof, witnessInput WitnessInput) (Groth16Proof, error) {
	// Serialize the proof to JSON.
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommitedValuesDigest
	encodedProof := hex.EncodeToString(proofBytes)

	return Groth16Proof{
		PublicInputs: publicInputs,
		EncodedProof: encodedProof,
	}, nil
}

// Function to deserialize a hex encoded proof to a groth16.Proof.
func DeserializeSP1Groth16Proof(encodedProof string) (*groth16.Proof, error) {
	decodedBytes, err := hex.DecodeString(encodedProof)
	if err != nil {
		return nil, fmt.Errorf("decoding hex proof: %w", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(decodedBytes)); err != nil {
		return nil, fmt.Errorf("reading proof from buffer: %w", err)
	}

	return &proof, nil
}

func LoadWitnessInputFromPath(path string) (WitnessInput, error) {
	// Read the file.
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		panic(err)
	}

	return inputs, nil
}

func NewCircuitFromWitness(witnessInput WitnessInput) Circuit {
	// Load the vars, felts, and exts from the witness input.
	vars := make([]frontend.Variable, len(witnessInput.Vars))
	felts := make([]babybear_v2.Variable, len(witnessInput.Felts))
	exts := make([]babybear_v2.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = babybear_v2.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = babybear_v2.NewE(witnessInput.Exts[i])
	}

	// Initialize the circuit.
	return Circuit{
		Vars:                 vars,
		Felts:                felts,
		Exts:                 exts,
		VkeyHash:             witnessInput.VkeyHash,
		CommitedValuesDigest: witnessInput.CommitedValuesDigest,
	}
}

// WriteToFile takes a filename and an object that implements io.WriterTo,
// and writes the object's data to the specified file.
func WriteToFile(filename string, writerTo io.WriterTo) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = writerTo.WriteTo(file)
	if err != nil {
		return err
	}

	return nil
}
