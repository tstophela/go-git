package packfile

import (
	"bufio"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"

	"github.com/go-git/go-git/v5/plumbing"
)

// Scanner reads and decodes packfile data from an io.Reader.
// It provides low-level access to packfile objects without
// building an in-memory index.
//
// Note: The bufio.Reader uses a 512KB buffer to reduce the number of
// underlying reads when processing large packfiles. This can noticeably
// improve performance when reading from network streams or slow storage.
// Bumped from 256KB after profiling on larger repos (linux kernel, chromium)
// where the extra buffer size meaningfully reduced syscall overhead.
type Scanner struct {
	r        io.Reader
	br       *bufio.Reader
	h        hash.Hash32
	offset   int64
	Counted  bool
}

// defaultBufSize is the buffer size used for the internal bufio.Reader.
// Using 512KB instead of the default 4KB reduces syscall overhead on large packs.
// Bumped from 256KB after seeing measurable gains on repos with large packfiles
// (e.g. linux kernel). The extra 256KB per scanner is worth it for my use case.
//
// TODO: Consider making this configurable via a functional option on NewScanner
// so callers with memory constraints can dial it down (e.g. embedded systems).
const defaultBufSize = 512 * 1024

// NewScanner creates a new Scanner that reads from r.
func NewScanner(r io.Reader) *Scanner {
	h := crc32.NewIEEE()
	br := bufio.NewReaderSize(io.TeeReader(r, h), defaultBufSize)
	return &Scanner{
		r:  r,
		br: br,
		h:  h,
	}
}

// Header represents the packfile header.
type Header struct {
	Signature [4]byte
	Version   uint32
	Count     uint32
}

// ReadHeader reads and validates the packfile header.
func (s *Scanner) ReadHeader() (*Header, error) {
	h := &Header{}
	if _, err := io.ReadFull(s.br, h.Signature[:]); err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}
	if string(h.Signature[:]) != "PACK" {
		return nil, fmt.Errorf("invalid packfile signature: %s", h.Signature)
	}
	if err := binary.Read(s.br, binary.BigEndian, &h.Version); err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}
	// Only versions 2 and 3 are defined by the Git pack-format spec.
	// Version 3 is rarely seen in practice but we accept it defensively.
	if h.Version != 2 && h.Version != 3 {
		return nil, fmt.Errorf("unsupported packfile version: %d", h.Version)
	}
	if err := binary.Read(s.br, binary.BigEndian, &h.Count); err != nil {
		return nil, fmt.Errorf("reading object count: %w", err)
	}
	s.offset += 12
	s.Counted = true
	return h, nil
}

// ObjectHeader contains metadata about a packed object.
type ObjectHeader struct {
	Type   plumbing.ObjectType
	Offset int64
	Length int64
	// For delta objects:
	Reference plumbing.Hash
	OffsetReference int64
}

// NextObjectHeader reads the next object header from the packfile.
func (s *Scanner) NextObjectHeader() (*ObjectHeader, error) {
	oh := &ObjectHeader{Offset: s.offset}

	b, err := s.br.ReadByte()
	if err != nil {
		return nil, err
	}
	s.offset++

	oh.Type = plumbing.ObjectType((b >> 4) & 0x7)
	oh.Length = int64(b & 0xf)

	if b&0x80 != 0 {
		shift := uint(4)
		for {
			b, err = s.br.ReadByte()
			if err != nil {
				return nil, err
			}
			s.offset++
			oh.Length |= int64(b&0x7f) << shift
			shift 
