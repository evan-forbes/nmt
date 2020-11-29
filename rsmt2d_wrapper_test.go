package nmt

import (
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/lazyledger/nmt/namespace"
	"github.com/lazyledger/rsmt2d"
)

func TestVCPRoots(t *testing.T) {
	eds, err := rsmt2d.ComputeExtendedDataSquare([][]byte{{1, 2}}, rsmt2d.RSGF8)
	if err != nil {
		panic(err)
	}
	vcp := NewVCP(eds, sha256.New, InitialCapacity(2), NamespaceIDSize(1))
	if !reflect.DeepEqual(vcp.Commitment(rsmt2d.Row, 0), vcp.Commitment(rsmt2d.Column, 0)) {
		t.Errorf("computing roots failed; expecting row and column roots for 1x1 square to be equal")
	}
}

func TestVCPProofs(t *testing.T) {
	nameSpacedShares := []namespace.Data{
		namespace.NewPrefixedData(namespace.IDSize(1), []byte{1, 1}),
		namespace.NewPrefixedData(namespace.IDSize(1), []byte{2, 2}),
		namespace.NewPrefixedData(namespace.IDSize(1), []byte{3, 3}),
		namespace.NewPrefixedData(namespace.IDSize(1), []byte{4, 4}),
	}
	eds, err := rsmt2d.ComputeNamedExtendedDataSquare(nameSpacedShares, rsmt2d.RSGF8)
	if err != nil {
		panic(err)
	}
	vcp := NewVCP(eds, sha256.New, InitialCapacity(2), NamespaceIDSize(1))
	proof, err := vcp.Prove(rsmt2d.Row, 1)
	// should this be 0 ?!
	if len(proof.Set) != 0 {
		t.Errorf("computing row proof for (1, 1) in 2x2 square failed; expecting proof set of length 2")
	}
	if proof.Index != 1 {
		t.Errorf("computing row proof for (1, 1) in 2x2 square failed; expecting proof index of 1")
	}
	if proof.Leaves != 4 {
		t.Errorf("computing row proof for (1, 1) in 2x2 square failed; expecting number of leaves to be 2")
	}
	proof, err = vcp.Prove(rsmt2d.Column, 1)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	if len(proof.Set) != 0 {
		t.Errorf("computing column proof for (1, 1) in 2x2 square failed; expecting proof set of length 2")
	}
	if proof.Index != 1 {
		t.Errorf("computing column proof for (1, 1) in 2x2 square failed; expecting proof index of 1")
	}
	if proof.Leaves != 4 {
		t.Errorf("computing column proof for (1, 1) in 2x2 square failed; expecting number of leaves to be 2")
	}
}
