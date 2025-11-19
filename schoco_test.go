package biscuit

import (
	"crypto/rand"
	"testing"

	"github.com/hpe-usp-spire/schoco"
	"github.com/stretchr/testify/require"
)

func TestBiscuitThreeBlocks(t *testing.T) {
	rng := rand.Reader
	const rootKeyID = 123
	const contextText = "current_context"

	// --- Root key (schoco) ---
	privateRoot, publicRoot := schoco.KeyPair()

	// --- Builder + authority facts ---
	builder := NewBuilder(privateRoot, WithRNG(rng), WithRootKeyID(rootKeyID))
	// authority grants:
	//   - /a/file1 : read
	//   - /b/file2 : write
	builder.AddAuthorityFact(Fact{Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}}})
	builder.AddAuthorityFact(Fact{Predicate: Predicate{Name: "right", IDs: []Term{String("/b/file2"), String("write")}}})
	builder.SetContext(contextText)

	b1, err := builder.Build()
	require.NoError(t, err)
	t.Log("[DEBUG] Authority-only Biscuit built")

	// --- Block 2: caveat_read — requires right(resource, "read") when operation = "read" ---
	block2 := b1.CreateBlock()
	block2.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "must_have_right", IDs: []Term{Variable("R"), Variable("Op")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("R")}},
					{Name: "operation", IDs: []Term{Variable("Op")}},
					{Name: "right", IDs: []Term{Variable("R"), Variable("Op")}},
				},
			},
		},
	})
	b2, err := b1.Append(rng, block2.Build())
	require.NoError(t, err)
	t.Log("[DEBUG] Block 2 (caveat_read) appended")

	// --- Block 3: caveat_write — requires right(resource, "write") when operation = "write" ---
	block3 := b2.CreateBlock()
	block3.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "must_have_right2", IDs: []Term{Variable("R"), Variable("Op")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("R")}},
					{Name: "operation", IDs: []Term{Variable("Op")}},
					{Name: "right", IDs: []Term{Variable("R"), Variable("Op")}},
				},
			},
		},
	})
	b3, err := b2.Append(rng, block3.Build())
	require.NoError(t, err)
	t.Log("[DEBUG] Block 3 (caveat_write) appended")

	// --- Block 4: caveat_general — just demonstrates a third block with a simple check ---
	block4 := b3.CreateBlock()
	block4.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat_general", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("0")}},
				},
			},
		},
	})
	b4, err := b3.Append(rng, block4.Build())
	require.NoError(t, err)
	t.Log("[DEBUG] Block 4 (caveat_general) appended")

	// --- Serialize/Deserialize final biscuit to ensure round-trip works ---
	b4ser, err := b4.Serialize()
	require.NoError(t, err)
	b4deser, err := Unmarshal(b4ser)
	require.NoError(t, err)
	t.Log("[DEBUG] Biscuit fully serialized and deserialized")

	// --- Authorization checks using the biscuit deserialized ---
	// Case A: /a/file1 read  -> should be allowed (authority has right("/a/file1","read"))
	authA, err := b4deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	authA.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}})
	authA.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}})
	authA.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, authA.Authorize())
	t.Log("[DEBUG] /a/file1 read authorized (expected)")

	// Case B: /a/file1 write -> should be denied (authority does not have right("/a/file1","write"))
	authB, err := b4deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	authB.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}})
	authB.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("write")}}})
	authB.AddPolicy(DefaultAllowPolicy)
	require.Error(t, authB.Authorize())
	t.Log("[DEBUG] /a/file1 write denied (expected)")

	// Case C: /b/file2 read -> should be denied (authority only grants write on /b/file2)
	authC, err := b4deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	authC.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/b/file2")}}})
	authC.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}})
	authC.AddPolicy(DefaultAllowPolicy)
	require.Error(t, authC.Authorize())
	t.Log("[DEBUG] /b/file2 read denied (expected)")
}

func TestBiscuitSeal(t *testing.T) {
	rng := rand.Reader
	privateRoot, publicRoot := schoco.KeyPair()

	// --- Cria builder ---
	builder := NewBuilder(privateRoot, WithRNG(rng))
	builder.AddAuthorityFact(Fact{Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}}})

	// --- Cria Biscuit ---
	b, err := builder.Build()
	require.NoError(t, err)
	require.False(t, b.sealed, "Biscuit original não deve estar sealed")

	// --- Cria um bloco extra ---
	block := b.CreateBlock()
	block.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "can_read", IDs: []Term{Variable("res")}},
				Body: []Predicate{
					{Name: "right", IDs: []Term{Variable("res"), String("read")}},
				},
			},
		},
	})
	b2, err := b.Append(rng, block.Build())
	require.NoError(t, err)

	// --- Seal do Biscuit ---
	sealedB := b2.Seal()
	require.True(t, sealedB.sealed, "Biscuit selado deve ter sealed = true")
	require.False(t, b2.sealed, "Biscuit original não deve ser alterado")

	// --- Teste de autorização com sealed Biscuit ---
	auth, err := sealedB.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	auth.AddFact(Fact{Predicate: Predicate{Name: "res", IDs: []Term{String("/a/file1")}}})
	auth.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, auth.Authorize(), "Biscuit selado deve autorizar corretamente")
}

func TestBiscuitSealAndAppend(t *testing.T) {
	rng := rand.Reader

	// --- Cria chave root ---
	privateRoot, _ := schoco.KeyPair()

	// --- Builder e authority facts ---
	builder := NewBuilder(privateRoot)
	builder.AddAuthorityFact(Fact{Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}}})

	// --- Cria o Biscuit ---
	b, err := builder.Build()
	require.NoError(t, err)
	t.Log("[DEBUG] Authority-only Biscuit built")

	// --- Selar o Biscuit ---
	sealed := b.Seal()
	require.True(t, sealed.sealed)
	t.Log("[DEBUG] Biscuit sealed")

	// --- Tenta adicionar um bloco após selagem ---
	newBlock := sealed.CreateBlock()
	newBlock.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "test_check", IDs: []Term{Variable("res")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("res")}},
				},
			},
		},
	})

	_, err = sealed.Append(rng, newBlock.Build())
	require.Error(t, err) // ✅ deve falhar
	t.Log("[DEBUG] Append to sealed Biscuit correctly failed")
}
