package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/blacktop/lzss"
)

var inFile = flag.String("input_filename", "srec.out.00020000.bin", "input filename")
var outPrefix = flag.String("output_prefix", "unnand/out", "output filename prefix")

const pageSize = 0x800
const oobSize = 0x40

func removeOOB(data []byte) ([]byte, error) {
	if len(data)%(pageSize+oobSize) != 0 {
		return nil, fmt.Errorf("data (len = 0x%x) is not a multiple of 0x%x+0x%0x", len(data), pageSize, oobSize)
	}

	ret := make([]byte, 0, len(data)/(pageSize+oobSize)*pageSize)
	for i := 0; i < len(data); i += pageSize + oobSize {
		ret = append(ret, data[i:i+pageSize]...)
	}

	return ret, nil
}

func uint32be(b []byte) uint32 {
	return (uint32(b[0]) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | uint32(b[3])
}

type flashHeader struct {
	magic                uint32
	headerSize           uint32
	pageSize1, pageSize2 uint32
	bmpSize              uint32
	loadAddr, loadSize   uint32
	execAddr             uint32
}

func parseHeader(data []byte) (*flashHeader, error) {
	if len(data) < 0x44 {
		return nil, fmt.Errorf("data too short (0x%x), expect at least 0x44 bytes header", len(data))
	}

	for i := 0; i < 0x44; i += 4 {
		log.Printf("header[0x%02x]: 0x%08x", i, uint32be(data[i:]))
	}

	valAt := func(i uint) uint32 {
		return (uint32(data[i]) << 24) | (uint32(data[i+1]) << 16) | (uint32(data[i+2]) << 8) | uint32(data[i+3])
	}

	return &flashHeader{
		magic:      valAt(0x00),
		headerSize: valAt(0x08),
		pageSize1:  valAt(0x10),
		pageSize2:  valAt(0x14),
		bmpSize:    valAt(0x1c),
		loadAddr:   valAt(0x30),
		loadSize:   valAt(0x34),
		execAddr:   valAt(0x3c),
	}, nil
}

type segmentInfo struct {
	name                     string
	start, size, flags, dest uint32
}

func (si *segmentInfo) String() string {
	dst := ""
	if si.dest != 0 {
		dst = fmt.Sprintf(" => 0x%08x", si.dest)
	}
	return fmt.Sprintf("section %q [0x%08x-0x%08x] flags 0x%x%s", si.name, si.start, si.start+si.size-1, si.flags, dst)
}

type segment struct {
	start uint32
	data  []byte
	info  *segmentInfo
}

func (s *segment) size() uint32 {
	return uint32(len(s.data))
}

func (s *segment) hasAddr(addr uint32) bool {
	return addr >= s.start && addr < s.start+s.size()
}

func (s *segment) String() string {
	if s.info != nil {
		return s.info.String()
	}
	return fmt.Sprintf("[0x%08x-0x%08x]", s.start, s.start+s.size()-1)
}

type memory struct {
	s []*segment
}

func (m *memory) segmentFor(addr uint32) (*segment, bool) {
	for _, s := range m.s {
		if s.hasAddr(addr) {
			return s, true
		}
	}
	return nil, false
}

func (m *memory) slice(low, high uint32) ([]byte, error) {
	ss, ok := m.segmentFor(low)
	if !ok {
		return nil, fmt.Errorf("no segment for 0x%08x found", low)
	}

	if high == 0 {
		high = ss.start + ss.size() + 1
	} else {
		es, ok := m.segmentFor(high - 1)
		if !ok {
			return nil, fmt.Errorf("no segment for 0x%08x found", high-1)
		}

		if ss != es {
			return nil, fmt.Errorf("memory[0x%08x:0x%08x] not contiguous, start segment: %v, end segment: %v", ss, es)
		}
	}

	lowIdx, highIdx := low-ss.start, high-ss.start
	return ss.data[lowIdx:highIdx], nil
}

func (m *memory) uint32be(addr uint32) (uint32, error) {
	b, err := m.slice(addr, addr+4)
	if err != nil {
		return 0, fmt.Errorf("can't get uint32 from 0x%08x: %w", addr, err)
	}

	return (uint32(b[0]) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | uint32(b[3]), nil
}

func (m *memory) cstring(addr uint32) (string, error) {
	b, err := m.slice(addr, 0)
	if err != nil {
		return "", err
	}
	//log.Printf("cstring(%x), b = %q", addr, b)

	zero := bytes.IndexByte(b, byte(0))
	if zero < 0 {
		return "", errors.New("string terminator not found")
	}

	return string(b[:zero]), nil
}

func (m *memory) cstringptr(ptr uint32) (string, error) {
	addr, err := m.uint32be(ptr)
	if err != nil {
		return "", err
	}
	return m.cstring(addr)
}

func (m *memory) addSegment(start uint32, data []byte, info *segmentInfo) (*segment, error) {
	ns := &segment{start, data, info}

	s, ok := m.segmentFor(ns.start)
	if !ok {
		s, ok = m.segmentFor(ns.start + ns.size() - 1)
	}
	if ok {
		return nil, fmt.Errorf("segment %v overlaps with existing segment %v", ns, s)
	}

	m.s = append(m.s, ns)
	return ns, nil
}

func (m *memory) memset(addr, val, count uint32, si *segmentInfo) error {
	log.Printf("memset(0x%x, %d, %d)", addr, val, count)
	if count != si.size {
		return fmt.Errorf("requested to memset %d bytes, but segment has %d bytes", count, si.size)
	}
	if val != 0 {
		return errors.New("can only memset to zero")
	}

	data := make([]byte, count)
	_, err := m.addSegment(addr, data, si)
	return err
}

func (m *memory) memcpy(dst, src, count uint32, si *segmentInfo) error {
	log.Printf("memcpy(0x%x, 0x%x, %d)", dst, src, count)
	if count != si.size {
		return fmt.Errorf("requested to memcpy %d bytes, but segment has %d bytes", count, si.size)
	}

	data, err := m.slice(src, src+count)
	if err != nil {
		return err
	}
	_, err = m.addSegment(dst, data, si)
	return err
}

func (m *memory) uncompress(dst, src, count uint32, si *segmentInfo) error {
	log.Printf("uncompress(0x%x, 0x%x, %d)", dst, src, count)

	cdata, err := m.slice(src, src+count)
	if err != nil {
		return err
	}
	data := lzss.Decompress(cdata)
	if uint32(len(data)) != si.size {
		return fmt.Errorf("uncompress inflated %d to %d bytes, but segment has %d bytes", count, len(data), si.size)
	}

	_, err = m.addSegment(dst, data, si)
	return err
}

func dumpApp(h *flashHeader, data []byte) (*memory, error) {
	apphdr := bytes.Index(data, []byte{0x3c, 0xa5, 0x5a, 0x3c})
	if apphdr < 0 {
		return nil, errors.New("app header not found")
	}

	m := &memory{}
	flashSeg, err := m.addSegment(h.loadAddr, data, nil)
	if err != nil {
		return nil, fmt.Errorf("can't add flash to load addr: %w", err)
	}
	hdrAddr := h.loadAddr + uint32(apphdr)

	var hf [25]uint32
	for i := uint32(0); i < uint32(len(hf)); i++ {
		val, err := m.uint32be(hdrAddr + i*4)
		if err != nil {
			return nil, fmt.Errorf("can't retrieve header field #%d: %w", i, err)
		}
		hf[i] = val
	}
	log.Printf("header fields: %#v", hf)

	si := make(map[uint32]*segmentInfo)
	secAddr := hf[16]
	for secAddr != 0 {
		var sf [6]uint32
		for i := uint32(0); i < uint32(len(sf)); i++ {
			val, err := m.uint32be(secAddr + i*4)
			if err != nil {
				return nil, fmt.Errorf("can't retrieve section field #%d: %w", i, err)
			}
			sf[i] = val
		}
		log.Printf("segmentInfo fields: %#v", sf)

		name, err := m.cstring(sf[1])
		if err != nil {
			return nil, fmt.Errorf("can't retrieve section name: %w", err)
		}
		start := sf[2]
		if exist, ok := si[start]; ok {
			return nil, fmt.Errorf("duplicate section definition for 0x%08x, prev = %s, curr = %s", start, exist.name, name)
		}

		size := sf[3]
		if size > 0 {
			si[start] = &segmentInfo{
				name:  name,
				start: start,
				size:  size,
				flags: sf[4],
				dest:  sf[5],
			}
		}

		secAddr = sf[0]
	}

	flashSegInfo, ok := si[h.loadAddr]
	if !ok {
		return nil, fmt.Errorf("section for flash at 0x%08x not found", h.loadAddr)
	}
	flashSeg.info = flashSegInfo
	delete(si, h.loadAddr)

	funcs := []struct {
		name       string
		f          func(_, _, _ uint32, _ *segmentInfo) error
		startField uint32
		endField   uint32
	}{
		{"memset", m.memset, 18, 19},
		{"memcpy", m.memcpy, 20, 21},
		{"uncompress", m.uncompress, 23, 24},
	}

	for _, f := range funcs {
		startAddr, endAddr := hf[f.startField], hf[f.endField]
		for addr := startAddr; addr < endAddr; addr += 12 {
			var args [3]uint32
			for i := uint32(0); i < uint32(len(args)); i++ {
				val, err := m.uint32be(addr + i*4)
				if err != nil {
					return nil, fmt.Errorf("can't retrieve function arg #%d: %w", i, err)
				}
				args[i] = val
			}

			dst, size := args[0], args[2]
			if size == 0 {
				continue
			}

			info, ok := si[dst]
			if !ok {
				return nil, fmt.Errorf("no section information for %s(%08x, ...) call", f.name, dst)
			}
			if err := f.f(args[0], args[1], args[2], info); err != nil {
				return nil, fmt.Errorf("can't %s: %w", f.name, err)
			}
			delete(si, dst)
		}
	}

	return m, nil
}

func main() {
	flag.Parse()

	data, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Read %d bytes from %s", len(data), *inFile)

	data, err = removeOOB(data)
	if err != nil {
		log.Fatalf("can't remove OOB data: %v", err)
	}

	log.Printf("%d bytes after OOB removal", len(data))
	if err := os.WriteFile(*outPrefix+".nooob.bin", data, 0666); err != nil {
		log.Fatalf("Can't write no-oob data: %v", err)
	}

	header, err := parseHeader(data)
	if err != nil {
		log.Fatalf("can't parse header: %v", err)
	}

	log.Printf("header: %#v", header)

	if header.pageSize1 != pageSize {
		log.Fatalf("header.PageSize1 (0x%x) != pageSize (0x%x)", header.pageSize1, pageSize)
	}

	bmp := data[pageSize : pageSize+header.bmpSize]
	if err := os.WriteFile(*outPrefix+".boot.bmp", bmp, 0666); err != nil {
		log.Fatalf("Can't write bitmap: %v", err)
	}

	codeStart := pageSize + header.bmpSize
	if rem := codeStart % pageSize; rem != 0 {
		codeStart += pageSize - rem
	}
	log.Printf("Code start at 0x%x", codeStart)

	code := data[codeStart : codeStart+header.loadSize]
	if err := os.WriteFile(*outPrefix+".code.bin", code, 0666); err != nil {
		log.Fatalf("Can't write code: %v", err)
	}

	if rem := len(data) - int(codeStart+header.loadSize); rem >= pageSize {
		log.Fatalf("Remaining data (len = 0x%x) after code >= pageSize (0x%x)", rem, pageSize)
	}

	mem, err := dumpApp(header, code)
	if err != nil {
		log.Fatalf("Can't dump app: %v", err)
	}

	for _, s := range mem.s {
		fn := fmt.Sprintf("%s.0x%08x%s.bin", *outPrefix, s.start, s.info.name)
		if err := os.WriteFile(fn, s.data, 0666); err != nil {
			log.Fatalf("Can't write segment: %v", err)
		}

		log.Printf("Wrote %v (%d bytes) to %v", s, s.size(), fn)
	}
}
