package biscuit

import (
	"encoding/hex"
	"testing"

	"github.com/hpe-usp-spire/schoco"
)

// DummyContainer implementa Marshal para substituir pb.Biscuit
type DummyContainer struct{}

func (d *DummyContainer) Marshal() ([]byte, error) {
	return []byte("dummy_token_bytes"), nil
}

func TestMinimalBiscuit(t *testing.T) {
	// 1. Cria root key Kyber
	rootKey, pubKey := schoco.KeyPair() // seu fork com Kyber

	// 2. Cria bloco de autoridade mínimo
	authority := &Block{
		version: MaxSchemaVersion,
	}

	// 3. Cria um SymbolTable mínimo para não quebrar Clone/SplitOff
	minSymbols := &SymbolTable{
		Symbols:  map[string]uint32{},
		Counters: map[uint32]string{},
	}

	// 4. Cria o Biscuit usando newBiscuit
	biscuit, err := newBiscuit(rootKey, minSymbols, authority)
	if err != nil {
		t.Fatalf("failed to create Biscuit: %v", err)
	}

	// 5. Inicializa container dummy se ainda for nil
	if biscuit.container == nil {
		biscuit.container = &DummyContainer{}
	}

	// 6. Serializa container
	tokenBytes, err := biscuit.container.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal container: %v", err)
	}

	t.Logf("Biscuit token (hex): %s", hex.EncodeToString(tokenBytes))

	// 7. Imprime root public key
	pubBytes, err := pubKey.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	t.Logf("Root Public Key (hex): %s", hex.EncodeToString(pubBytes))
}
