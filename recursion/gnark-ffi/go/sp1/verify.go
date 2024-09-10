package sp1

import (
	"bytes"
	"encoding/hex"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

func Verify(verifyCmdDataDir string, verifyCmdProof string, verifyCmdVkeyHash string, verifyCmdCommitedValuesDigest string) error {
	// Sanity check the required arguments have been provided.
	if verifyCmdDataDir == "" {
		panic("--data is required")
	}

	// Decode the proof.
	proofDecodedBytes, err := hex.DecodeString(verifyCmdProof)
	if err != nil {
		panic(err)
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofDecodedBytes)); err != nil {
		panic(err)
	}

	// Read the verifier key.
	vkFile, err := os.Open(verifyCmdDataDir + "/" + vkPath)
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Compute the public witness.
	circuit := Circuit{
		Vars:                 []frontend.Variable{},
		Felts:                []babybear.Variable{},
		Exts:                 []babybear.ExtensionVariable{},
		VkeyHash:             verifyCmdVkeyHash,
		CommitedValuesDigest: verifyCmdCommitedValuesDigest,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = plonk.Verify(proof, vk, publicWitness)
	return err
}

func VerifySolidity(verifyCmdDataDir string, verifyCmdProof string, verifyCmdVkeyHash string, verifyCmdCommitedValuesDigest string) error {
	// Sanity check the required arguments have been provided.
	if verifyCmdDataDir == "" {
		panic("--data is required")
	}

	// Decode the proof.
	proofDecodedBytes, err := hex.DecodeString(verifyCmdProof)
	if err != nil {
		panic(err)
	}

	// Proof contains 768 bytes worth of initial elements, followed by 32 bytes x nbCommits, followed by 64 bytes x nbCommits
	nbCommits := (len(proofDecodedBytes) - 768) / 32 / 3;

	proof_bn254 := plonk_bn254.UnmarshalSolidity(proofDecodedBytes, nbCommits) 

	// Read the verifier key.
	vkFile, err := os.Open(verifyCmdDataDir + "/" + vkPath)
	if err != nil {
		panic(err)
	}
	var vk plonk_bn254.VerifyingKey
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		panic(err)
	}

	// Compute the public witness.
	circuit := Circuit{
		Vars:                 []frontend.Variable{},
		Felts:                []babybear.Variable{},
		Exts:                 []babybear.ExtensionVariable{},
		VkeyHash:             verifyCmdVkeyHash,
		CommitedValuesDigest: verifyCmdCommitedValuesDigest,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	var witness_vec fr.Vector
	if value, ok := publicWitness.Vector().(fr.Vector); ok {
		witness_vec = value
	} else {
		panic("witness is not a vector")
	}

	// Verify proof.
	err = plonk_bn254.Verify(&proof_bn254, &vk, witness_vec)
	return err
}