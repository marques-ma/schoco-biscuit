// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/rand"

	"errors"
	"fmt"
	"io"
	"crypto/sha256"
    "encoding/hex"


	"github.com/marques-ma/schoco-biscuit/datalog"
	"github.com/marques-ma/schoco-biscuit/pb"

	"google.golang.org/protobuf/proto"
	"github.com/hpe-usp-spire/schoco"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// Biscuit represents a valid Biscuit token
// It contains multiple `Block` elements, the associated symbol table,
// and a serialized version of this data
type Biscuit struct {
	authority *Block
	blocks    []*Block
	symbols   *datalog.SymbolTable
	container *pb.Biscuit
	rootPubKey []byte
	sealed	bool
}

var (
	curve = edwards25519.NewBlakeSHA256Ed25519()
	g = curve.Point().Base()


	// ErrSymbolTableOverlap is returned when multiple blocks declare the same symbols
	ErrSymbolTableOverlap = errors.New("biscuit: symbol table overlap")
	// ErrInvalidAuthorityIndex occurs when an authority block index is not 0
	ErrInvalidAuthorityIndex = errors.New("biscuit: invalid authority index")
	// ErrInvalidAuthorityFact occurs when an authority fact is an ambient fact
	ErrInvalidAuthorityFact = errors.New("biscuit: invalid authority fact")
	// ErrInvalidBlockFact occurs when a block fact provides an authority or ambient fact
	ErrInvalidBlockFact = errors.New("biscuit: invalid block fact")
	// ErrInvalidBlockRule occurs when a block rule generate an authority or ambient fact
	ErrInvalidBlockRule = errors.New("biscuit: invalid block rule")
	// ErrEmptyKeys is returned when verifying a biscuit having no keys
	ErrEmptyKeys = errors.New("biscuit: empty keys")
	// ErrNoPublicKeyAvailable is returned when no public root key is available to verify the
	// signatures on a biscuit's blocks.
	ErrNoPublicKeyAvailable = errors.New("biscuit: no public key available")
	// ErrUnknownPublicKey is returned when verifying a biscuit with the wrong public key
	ErrUnknownPublicKey = errors.New("biscuit: unknown public key")

	ErrInvalidSignature = errors.New("biscuit: invalid signature")

	ErrInvalidSignatureSize = errors.New("biscuit: invalid signature size")

	ErrInvalidKeySize = errors.New("biscuit: invalid key size")

	UnsupportedAlgorithm = errors.New("biscuit: unsupported signature algorithm")
)

type biscuitOptions struct {
	rng       io.Reader
	rootKeyID *uint32
}

type biscuitOption interface {
	applyToBiscuit(*biscuitOptions) error
}

func newBiscuit(root kyber.Scalar, baseSymbols *datalog.SymbolTable, authority *Block, opts ...biscuitOption) (*Biscuit, error) {
    rootPubKey := curve.Point().Mul(root, g)
    schocoRootPubKey, err := schoco.PointToByte(rootPubKey)
    if err != nil {
        return nil, err
    }

    options := biscuitOptions{
        rng: rand.Reader,
    }
    for _, opt := range opts {
        if err := opt.applyToBiscuit(&options); err != nil {
            return nil, err
        }
    }

    symbols := baseSymbols.Clone()
    if !symbols.IsDisjoint(authority.symbols) {
        return nil, ErrSymbolTableOverlap
    }
    symbols.Extend(authority.symbols)

    protoAuthority, err := tokenBlockToProtoBlock(authority)
    if err != nil {
        return nil, err
    }
    marshalledAuthority, err := proto.Marshal(protoAuthority)
    if err != nil {
        return nil, err
    }

    // assinatura Schoco
    msg := string(marshalledAuthority)
    signature := schoco.StdSign(fmt.Sprintf("%s", msg), root)
    sigBytes, err := signature.ToByte()
    if err != nil {
        return nil, err
    }

    algorithm := pb.PublicKey_Ed25519

    // dummy nextKey para satisfazer protobuf
    nextKey := &pb.PublicKey{
        Algorithm: &algorithm,
        Key:       []byte{}, // dummy 32 bytes
    }

    signedBlock := &pb.SignedBlock{
        Block:     marshalledAuthority,
        NextKey:   nextKey,
        Signature: sigBytes,
    }

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: []byte{},
		},
	}

    container := &pb.Biscuit{
        RootKeyId: options.rootKeyID,
        Authority: signedBlock,
        Proof:     proof,
    }

    return &Biscuit{
        authority: authority,
        symbols:   symbols,
        container: container,
        rootPubKey: schocoRootPubKey,
    }, nil
}

func New(rng io.Reader, root kyber.Scalar, baseSymbols *datalog.SymbolTable, authority *Block) (*Biscuit, error) {
	var opts []biscuitOption
	if rng != nil {
		opts = []biscuitOption{WithRNG(rng)}
	}
	return newBiscuit(root, baseSymbols, authority, opts...)
}

func (b *Biscuit) CreateBlock() BlockBuilder {
	return NewBlockBuilder(b.symbols.Clone())
}

// Append corrigido: preserva bytes brutos (marshalledBlock), substitui a assinatura anterior
// por Point bytes (R) dentro do container, e grava a nova SignedBlock com a assinatura completa.
// NOTA: não depende de um campo em memória para partialSigs — a validação vai reconstruí-los a partir do container.
func (b *Biscuit) Append(rng io.Reader, block *Block) (*Biscuit, error) {
	if b.sealed {
		return nil, errors.New("biscuit: token is sealed, cannot append")
	}

	// pega a assinatura atual (authority ou último bloco)
	prevSignature, err := LastBlockSignature(b)
	if err != nil {
		return nil, err
	}

	if !b.symbols.IsDisjoint(block.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	// clone biscuit fields and append new block (token structure in-memory)
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks)+1)
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}
	blocks[len(b.blocks)] = block

	symbols := b.symbols.Clone()
	symbols.Extend(block.symbols)

	// serialize the new block (these bytes are what we sign & later store)
	protoBlock, err := tokenBlockToProtoBlock(block)
	if err != nil {
		return nil, err
	}
	marshalledBlock, err := proto.Marshal(protoBlock)
	if err != nil {
		return nil, err
	}

	// convert previous signature bytes to schoco Signature
	prevSig, err := schoco.ByteToSignature(prevSignature)
	if err != nil {
		return nil, err
	}

	// aggregate: this returns a partial signature point (to store replacing previous signature)
	// and a new full signature for the new block
	partSig, lastSig := schoco.Aggregate(string(marshalledBlock), prevSig)

	// convert partial point -> bytes and replace the previous signature in the serialized container
	p2Byte, err := schoco.PointToByte(partSig)
	if err != nil {
		return nil, err
	}
	if err := ReplaceLastBlockSignature(b, p2Byte); err != nil {
		return nil, err
	}

	// full signature for the new block -> bytes
	sig2Byte, err := lastSig.ToByte()
	if err != nil {
		return nil, err
	}

	algorithm := pb.PublicKey_Ed25519
	nextKey := &pb.PublicKey{
		Algorithm: &algorithm,
		Key:       []byte{},
	}

	signedBlock := &pb.SignedBlock{
		Block:     marshalledBlock,
		NextKey:   nextKey,
		Signature: sig2Byte,
	}

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: []byte{},
		},
	}

	// clone container and append new signed block
	container := &pb.Biscuit{
		Authority: b.container.Authority,
		Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
		Proof:     proof,
	}
	container.Blocks = append(container.Blocks, signedBlock)

	return &Biscuit{
		authority:   authority,
		blocks:      blocks,
		symbols:     symbols,
		container:   container,
	}, nil
}



func (b *Biscuit) Seal() *Biscuit {
    if b.sealed {
        return b
    }

    // clone fields para não alterar original
    authority := new(Block)
    *authority = *b.authority

    blocks := make([]*Block, len(b.blocks))
    for i, blk := range b.blocks {
        blocks[i] = new(Block)
        *blocks[i] = *blk
    }

	sig2Byte, err := LastBlockSignature(b)
	if err != nil {
		return nil
	}
	
	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: sig2Byte,
		},
	}

    container := &pb.Biscuit{
        Authority: b.container.Authority,
        Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
        RootKeyId: b.container.RootKeyId,
		Proof:     proof,
    }

    return &Biscuit{
        authority:  authority,
        blocks:     blocks,
        symbols:    b.symbols.Clone(),
        container:  container,
        rootPubKey: b.rootPubKey,
        sealed:     true,
    }
}

type (
	// A PublickKeyByIDProjection inspects an optional ID for a public key and returns the
	// corresponding public key, if any. If it doesn't recognize the ID or can't find the public
	// key, or no ID is supplied and there is no default public key available, it should return an
	// error satisfying errors.Is(err, ErrNoPublicKeyAvailable).
	PublickKeyByIDProjection func(*uint32) ([]byte, error)
)

// WithSingularRootPublicKey supplies one public key to use as the root key with which to verify the
// signatures on a biscuit's blocks.
func WithSingularRootPublicKey(key kyber.Point) PublickKeyByIDProjection {
    return func(*uint32) ([]byte, error) {
        buf, err := key.MarshalBinary()
        if err != nil {
            return nil, err
        }
        return buf, nil
    }
}

// WithRootPublicKeys supplies a mapping to public keys from their corresponding IDs, used to select
// which public key to use to verify the signatures on a biscuit's blocks based on the key ID
// embedded within the biscuit when it was created. If the biscuit has no key ID available, this
// function selects the optional default key instead. If no public key is available—whether for the
// biscuit's embedded key ID or a default key when no such ID is present—it returns
// [ErrNoPublicKeyAvailable].
func WithRootPublicKeys(keysByID map[uint32]kyber.Point, defaultKey *kyber.Point) PublickKeyByIDProjection {
    return func(id *uint32) ([]byte, error) {
        if id == nil {
            if defaultKey != nil {
                buf, err := (*defaultKey).MarshalBinary()
                if err != nil {
                    return nil, err
                }
                return buf, nil
            }
        } else if key, ok := keysByID[*id]; ok {
            buf, err := key.MarshalBinary()
            if err != nil {
                return nil, err
            }
            return buf, nil
        }
        return nil, ErrNoPublicKeyAvailable
    }
}

func (b *Biscuit) authorizerFor(rootPubKey kyber.Point, opts ...AuthorizerOption) (Authorizer, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: empty container")
	}

	N := len(b.container.Blocks)
	// fmt.Printf("[DEBUG] Number of appended blocks: %d\n", N)

	// -----------------------
	// Caso trivial: apenas authority
	// -----------------------
	if N == 0 {
		sigBytes := b.container.Authority.Signature
		sig, err := schoco.ByteToSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("[DEBUG] Error converting authority signature to Signature: %v", err)
		}

		msg := fmt.Sprintf("%s", b.container.Authority.Block)
		// fmt.Printf("[DEBUG] Msg[Authority] SHA256: %s\n", sha256Hex([]byte(msg)))

		if !schoco.StdVerify(msg, sig, rootPubKey) {
			return nil, errors.New("invalid authority signature")
		}
		// fmt.Println("[DEBUG] Authority-only signature verified")
		return NewVerifier(b, opts...)
	}

	// -----------------------
	// Token estendido
	// -----------------------
	setMessages := make([]string, 0, N+1)
	setPartSig := make([]kyber.Point, 0, N)

	// 1) Extrai R do authority
	var authR kyber.Point
	authBytes := b.container.Authority.Signature
	if pt, err := schoco.ByteToPoint(authBytes); err == nil {
		authR = pt
		// fmt.Println("[DEBUG] Authority signature: extracted R point directly")
	} else if sig, err2 := schoco.ByteToSignature(authBytes); err2 == nil {
		authR = sig.R
		// fmt.Println("[DEBUG] Authority signature: extracted R from full Signature")
	} else {
		return nil, fmt.Errorf("[DEBUG] Cannot parse authority signature: %v / %v", err, err2)
	}

	// adiciona Authority como última partial signature
	setPartSig = append(setPartSig, authR)
	setMessages = append(setMessages, fmt.Sprintf("%s", b.container.Authority.Block))
	// fmt.Printf("[DEBUG] Msg[Authority] SHA256: %s\n", sha256Hex([]byte(b.container.Authority.Block)))
	// fmt.Printf("[DEBUG] PartialSig[Authority] (R hex): %x\n", authR)

	// 2) Extrai R de todos os blocos (0..N-2)
	for i := 0; i < N-1; i++ {
		sb := b.container.Blocks[i]
		if sb == nil {
			return nil, fmt.Errorf("[DEBUG] missing SignedBlock at index %d", i)
		}

		var pt kyber.Point
		if p, err := schoco.ByteToPoint(sb.Signature); err == nil {
			pt = p
			// fmt.Printf("[DEBUG] Block %d signature: extracted R point directly\n", i)
		} else if s, err2 := schoco.ByteToSignature(sb.Signature); err2 == nil {
			pt = s.R
			// fmt.Printf("[DEBUG] Block %d signature: extracted R from full Signature\n", i)
		} else {
			return nil, fmt.Errorf("[DEBUG] Cannot parse block %d signature: %v / %v", i, err, err2)
		}

		setPartSig = append(setPartSig, pt)
		setMessages = append(setMessages, fmt.Sprintf("%s", sb.Block))
		// fmt.Printf("[DEBUG] Msg[%d] SHA256: %s\n", i, sha256Hex([]byte(sb.Block)))
		// fmt.Printf("[DEBUG] PartialSig[%d] (R hex): %x\n", i, pt)
	}

	// 3) Último bloco -> assinatura completa
	lastSB := b.container.Blocks[N-1]
	if lastSB == nil {
		return nil, errors.New("[DEBUG] missing last SignedBlock")
	}
	lastSig, err := schoco.ByteToSignature(lastSB.Signature)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] cannot parse last block signature: %v", err)
	}
	setMessages = append(setMessages, fmt.Sprintf("%s", lastSB.Block))
	// fmt.Printf("[DEBUG] Msg[last] SHA256: %s\n", sha256Hex([]byte(lastSB.Block)))
	// fmt.Printf("[DEBUG] LastSig: (r=%x, s=%x)\n", lastSig.R, lastSig.S)

	// -----------------------
	// Inverte arrays para ordem esperada pelo Verify
	// -----------------------
	revMessages := reverseStrings(setMessages)
	revPartSig := reversePoints(setPartSig)

	if !schoco.Verify(rootPubKey, revMessages, revPartSig, lastSig) {
		fmt.Println("[DEBUG] Verification failed with these parameters:")
		for i, m := range revMessages {
			fmt.Printf("[DEBUG] msg[%d] SHA256=%s len=%d\n", i, sha256Hex([]byte(m)), len(m))
		}
		for i, p := range revPartSig {
			fmt.Printf("[DEBUG] part[%d] = %x\n", i, p)
		}
		fmt.Printf("[DEBUG] lastSig: r=%x s=%x\n", lastSig.R, lastSig.S)
		return nil, errors.New("invalid signature (extended)")
	}

	// fmt.Println("[DEBUG] Extended signature verified")
	return NewVerifier(b, opts...)
}


// AuthorizerFor selects from the supplied source a root public key to use to verify the signatures
// on the biscuit's blocks, returning an error satisfying errors.Is(err, ErrNoPublicKeyAvailable) if
// no such public key is available. If the signatures are valid, it creates an [Authorizer], which
// can then test the authorization policies and accept or refuse the request.
func (b *Biscuit) AuthorizerFor(keySource PublickKeyByIDProjection, opts ...AuthorizerOption) (Authorizer, error) {
    if keySource == nil {
        return nil, errors.New("root public key source must not be nil")
    }

    rootPublicKeyBytes, err := keySource(b.RootKeyID())
    if err != nil {
        return nil, fmt.Errorf("choosing root public key: %w", err)
    }
    if len(rootPublicKeyBytes) == 0 {
        return nil, ErrNoPublicKeyAvailable
    }

    // Prefer using schoco.ByteToPoint so behavior is consistent with other code
    rootPubPoint, err := schoco.ByteToPoint(rootPublicKeyBytes)
    if err != nil {
        return nil, fmt.Errorf("converting root public key to point: %w", err)
    }

    return b.authorizerFor(rootPubPoint, opts...)
}

// TODO: Add "Deprecated" note to the "(*Biscuit).Authorizer" method, recommending use of
// "(*Biscuit).AuthorizerFor" instead. Wait until after we release the module with the latter
// available, per https://go.dev/wiki/Deprecated.

// Authorizer checks the signature and creates an [Authorizer]. The Authorizer can then test the
// authorizaion policies and accept or refuse the request.
func (b *Biscuit) Authorizer(root kyber.Point, opts ...AuthorizerOption) (Authorizer, error) {
	return b.authorizerFor(root)
}

func (b *Biscuit) Checks() [][]datalog.Check {
	result := make([][]datalog.Check, 0, len(b.blocks)+1)
	result = append(result, b.authority.checks)
	for _, block := range b.blocks {
		result = append(result, block.checks)
	}
	return result
}

func (b *Biscuit) GetContext() string {
	if b == nil || b.authority == nil {
		return ""
	}

	return b.authority.context
}

func (b *Biscuit) Serialize() ([]byte, error) {
	return proto.Marshal(b.container)
}

var ErrFactNotFound = errors.New("biscuit: fact not found")

// GetBlockID returns the first block index containing a fact
// starting from the authority block and then each block in the order they were added.
// ErrFactNotFound is returned when no block contains the fact.
func (b *Biscuit) GetBlockID(fact Fact) (int, error) {
	// don't store symbols from searched fact in the verifier table
	symbols := b.symbols.Clone()
	datalogFact := fact.Predicate.convert(symbols)

	for _, f := range *b.authority.facts {
		if f.Equal(datalogFact) {
			return 0, nil
		}
	}

	for i, b := range b.blocks {
		for _, f := range *b.facts {
			if f.Equal(datalogFact) {
				return i + 1, nil
			}
		}
	}

	return 0, ErrFactNotFound
}

/*
// SHA256Sum returns a hash of `count` biscuit blocks + the authority block
// along with their respective keys.
func (b *Biscuit) SHA256Sum(count int) ([]byte, error) {
	if count < 0 {
		return nil, fmt.Errorf("biscuit: invalid count,  %d < 0 ", count)
	}
	if g, w := count, len(b.container.Blocks); g > w {
		return nil, fmt.Errorf("biscuit: invalid count,  %d > %d", g, w)
	}

	h := sha256.New()
	// write the authority block and the root key
	if _, err := h.Write(b.container.Authority); err != nil {
		return nil, err
	}
	if _, err := h.Write(b.container.Keys[0]); err != nil {
		return nil, err
	}

	for _, block := range b.container.Blocks[:count] {
		if _, err := h.Write(block); err != nil {
			return nil, err
		}
	}
	for _, key := range b.container.Keys[:count+1] { // +1 to skip the root key
		if _, err := h.Write(key); err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}*/

func (b *Biscuit) BlockCount() int {
	return len(b.container.Blocks)
}

func (b *Biscuit) RootKeyID() *uint32 {
	return b.container.RootKeyId
}

func (b *Biscuit) String() string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.String(b.symbols)
	}

	return fmt.Sprintf(`
Biscuit {
	symbols: %+q
	authority: %s
	blocks: %v
}`,
		*b.symbols,
		b.authority.String(b.symbols),
		blocks,
	)
}

func (b *Biscuit) Code() []string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.Code(b.symbols)
	}
	return blocks
}

/*
func (b *Biscuit) checkRootKey(root ed25519.PublicKey) error {
	if len(b.container.Keys) == 0 {
		return ErrEmptyKeys
	}
	if !bytes.Equal(b.container.Keys[0], root.Bytes()) {
		return ErrUnknownPublicKey
	}

	return nil
}*/

func (b *Biscuit) generateWorld(symbols *datalog.SymbolTable) (*datalog.World, error) {
	world := datalog.NewWorld()

	for _, fact := range *b.authority.facts {
		world.AddFact(fact)
	}

	for _, rule := range b.authority.rules {
		world.AddRule(rule)
	}

	for _, block := range b.blocks {
		for _, fact := range *block.facts {
			world.AddFact(fact)
		}

		for _, rule := range block.rules {
			world.AddRule(rule)
		}
	}

	if err := world.Run(symbols); err != nil {
		return nil, err
	}

	return world, nil
}

func (b *Biscuit) RevocationIds() [][]byte {
	result := make([][]byte, 0, len(b.blocks)+1)
	result = append(result, b.container.Authority.Signature)
	for _, block := range b.container.Blocks {
		result = append(result, block.Signature)
	}
	return result
}

// LastBlockSignature retorna os bytes da última assinatura (se houver blocos,
// retorna o Signature do último SignedBlock; caso contrário retorna a signature da Authority)
func LastBlockSignature(b *Biscuit) ([]byte, error) {
	if b == nil || b.container == nil {
		return nil, errors.New("biscuit is nil or has no container")
	}

	blocks := b.container.Blocks
	if len(blocks) == 0 {
		// sem blocos: use a assinatura da authority
		if b.container.Authority == nil || b.container.Authority.Signature == nil {
			return nil, errors.New("biscuit: authority has no signature")
		}
		return b.container.Authority.Signature, nil
	}

	last := blocks[len(blocks)-1]
	if last == nil || last.Signature == nil {
		return nil, errors.New("biscuit: last block has no signature")
	}
	return last.Signature, nil
}

// ReplaceLastBlockSignature substitui a assinatura do último elemento (se houver blocos,
// substitui o Signature do último SignedBlock; caso contrário, substitui a assinatura da Authority).
func ReplaceLastBlockSignature(b *Biscuit, newSig []byte) error {
	if b == nil || b.container == nil {
		return errors.New("biscuit is nil or has no container")
	}

	// Se não existem blocks, substitui a assinatura da Authority
	if len(b.container.Blocks) == 0 {
		if b.container.Authority == nil {
			return errors.New("biscuit: missing authority block")
		}
		b.container.Authority.Signature = newSig
		return nil
	}

	// Caso normal: substitui a assinatura do último SignedBlock
	lastIndex := len(b.container.Blocks) - 1
	b.container.Blocks[lastIndex].Signature = newSig
	return nil
}

// helper para SHA256 hex de um []byte
func sha256Hex(b []byte) string {
    h := sha256.Sum256(b)
    return hex.EncodeToString(h[:])
}

func reverseStrings(s []string) []string {
    r := make([]string, len(s))
    for i := range s {
        r[i] = s[len(s)-1-i]
    }
    return r
}
func reversePoints(p []kyber.Point) []kyber.Point {
    r := make([]kyber.Point, len(p))
    for i := range p {
        r[i] = p[len(p)-1-i]
    }
    return r
}
