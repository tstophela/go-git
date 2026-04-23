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
type Scanner struct {
	r        io.Reader
	br       *bufio.Reader
	h        hash.Hash32
	offset   int64
	Counted  bool
}

// NewScanner creates a new Scanner that reads from r.
func NewScanner(r io.Reader) *Scanner {
	h := crc32.NewIEEE()
	br := bufio.NewReader(io.TeeReader(r, h))
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
			shift += 7
			if b&0x80 == 0 {
				break
			}
		}
	}

	switch oh.Type {
	case plumbing.OFSDeltaObject:
		v, err := readVarint(s.br)
		if err != nil {
			return nil, fmt.Errorf("reading ofs-delta offset: %w", err)
		}
		s.offset += int64(varIntSize(v))
		oh.OffsetReference = oh.Offset - int64(v)
	case plumbing.REFDeltaObject:
		if _, err := io.ReadFull(s.br, oh.Reference[:]); err != nil {
			return nil, fmt.Errorf("reading ref-delta hash: %w", err)
		}
		s.offset += 20
	}

	return oh, nil
}

// NextObject reads the deflated content of the next object.
func (s *Scanner) NextObject(w io.Writer) (int64, error) {
	zr, err := zlib.NewReader(s.br)
	if err != nil {
		return 0, fmt.Errorf("creating zlib reader: %w", err)
	}
	defer zr.Close()

	n, err := io.Copy(w, zr)
	if err != nil {
		return n, fmt.Errorf("decompressing object: %w", err)
	}
	return n, nil
}

// readVarint reads a variable-length integer (big-endian, MSB continuation).
func readVarint(r io.ByteReader) (uint64, error) {
	var v uint64
	var b byte
	var err error
	b, err = r.ReadByte()
	if err != nil {
		return 0, err
	}
	v = uint64(b & 0x7f)
	for b&0x80 != 0 {
		v++
		b, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = (v << 7) | uint64(b&0x7f)
	}
	return v, nil
}

// varIntSize returns the number of bytes needed to encode v as a varint.
func varIntSize(v uint64) int {
	size := 1
	v >>= 7
	for v > 0 {
		v >>= 7
		size++
	}
	return size
}
