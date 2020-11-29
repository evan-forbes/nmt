package nmt

import (
	"hash"

	"github.com/lazyledger/nmt/namespace"
	"github.com/lazyledger/rsmt2d"
)

// NewVCP issues a new rsmt2d.VectorCommitmentProver that uses configured named
// spaced merkle trees to create proofs and commitments
func NewVCP(eds *rsmt2d.ExtendedDataSquare, hasher func() hash.Hash, setters ...Option) VCP {
	// default options:
	opts := &Options{
		InitialCapacity:    128,
		NamespaceIDSize:    32,
		IgnoreMaxNamespace: true,
	}

	for _, setter := range setters {
		setter(opts)
	}
	return VCP{
		setters:   setters,
		freshHash: hasher,
		eds:       eds,
		opts:      opts,
	}
}

// VCP uses configured name spaced merkle trees to adhere to the
// rsmt2d.VectorCommiterProver interface
type VCP struct {
	setters   []Option
	freshHash func() hash.Hash
	eds       *rsmt2d.ExtendedDataSquare
	opts      *Options
}

// Commitment returns the root of a selected row or column using a configured
// name space merkle tree. It also fullfills it's portion of the
// rsmt2d.VectorCommiterProver interface.
func (v VCP) Commitment(a rsmt2d.Axis, idx uint) []byte {
	// push all the data onto an nmt
	tree := New(v.freshHash(), v.setters...)
	leaves := v.fetchLeaves(a, idx)
	for _, leaf := range leaves {
		err := tree.Push(namespace.NewPrefixedData(tree.NamespaceSize(), leaf))
		if err != nil {
			panic(err)
		}
	}
	return tree.Root().Bytes()
}

// Prove issues an inclusion proof of a selected row or column using a
// configured name spaced merkle tree. It also fullfills it's portion of the
// rsmt2d.VectorCommiterProver interface.
func (v VCP) Prove(a rsmt2d.Axis, idx uint) (rsmt2d.Proof, error) {
	tree := New(v.freshHash(), v.setters...)
	leaves := v.fetchLeaves(a, idx)
	for _, leaf := range leaves {
		err := tree.Push(namespace.NewPrefixedData(tree.NamespaceSize(), leaf))
		if err != nil {
			panic(err)
		}
	}
	// ask(Ismail): is this correct proof to generate?
	proof, err := tree.ProveRange(0, len(leaves))
	if err != nil {
		return rsmt2d.Proof{}, err
	}
	return rsmt2d.Proof{
		Root:   tree.Root().Bytes(),
		Set:    proof.nodes,
		Index:  uint64(idx),
		Leaves: uint64(len(leaves)),
	}, nil
}

// fetchLeaves gets the column or row data from the underlying data
// square
func (v VCP) fetchLeaves(a rsmt2d.Axis, idx uint) [][]byte {
	// todo(evan): change to better optimize for data rectangles
	var leaves [][]byte
	switch a {
	case rsmt2d.Column:
		leaves = v.eds.Column(idx)
	case rsmt2d.Row:
		leaves = v.eds.Row(idx)
	}
	return leaves
}
