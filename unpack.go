package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/blacktop/lzss"
	"github.com/golang/glog"
)

var inFile = flag.String("input_filename", "", "name of input file")
var intermediatesPrefix = flag.String("intermediates_prefix", "", "if nonempty, writes intermediate files with this prefix")
var outPrefix = flag.String("output_prefix", "", "output filename prefix")
var flashPageSize = flag.Int("flash_page_size", 0x800, "flash page size")
var flashOOBsize = flag.Int("flash_oob_size", 0x40, "flash OOB data size")

type rasterState struct {
	height, width uint
	x, y          uint
	data, seed    []byte
	segment       uint
	compression   uint
	pad           bool
}

type pclParam struct {
	c    byte
	val  int
	sign byte
}

func (p *pclParam) String() string {
	s := ""
	if p.sign != 0 {
		s = fmt.Sprintf(", sign: %q", p.sign)
	}
	return fmt.Sprintf("{command %q, value %v%s}", p.c, p.val, s)
}

func splitGroup(g []byte) ([]*pclParam, error) {
	r := bytes.NewReader(g)

	var ret []*pclParam
	curr := &pclParam{}
	for r.Len() > 0 {
		b, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("can't read group byte: %w", err)
		}

		switch {
		case b == '+' || b == '-':
			curr.sign = b

		case b >= '0' && b <= '9':
			curr.val = (curr.val * 10) + int(b-'0')

		case b >= 96 && b <= 126:
			b -= 32
			fallthrough

		case b >= 64 && b <= 94:
			curr.c = b
			if curr.sign == '-' {
				curr.val = -curr.val
				curr.sign = 0
			}
			ret = append(ret, curr)
			curr = &pclParam{}

		default:
			return nil, fmt.Errorf("invalid group char %q", b)
		}
	}

	return ret, nil
}

func readExact(r io.Reader, buf []byte) error {
	pos := 0
	for pos < len(buf) {
		n, err := r.Read(buf[pos:])
		if err != nil {
			return fmt.Errorf("can't read %d bytes from buffer: %w", len(buf), err)
		}
		pos += n
	}
	return nil
}

func readPCL(r *bufio.Reader, s *rasterState) (uint, error) {
	var pos uint
	cmd, err := r.ReadByte()
	if err != nil {
		return pos, fmt.Errorf("unable to read command byte: %w", err)
	}
	pos += 1

	switch {
	case cmd >= 33 && cmd <= 47: // Parameterized Character
		buf := []byte{cmd}
		for {
			b, err := r.ReadByte()
			if err != nil {
				return pos, fmt.Errorf("unable to read until termination character: %w", err)
			}
			pos += 1
			buf = append(buf, b)
			if b >= 64 && b <= 94 { // Termination Character
				break
			}
		}
		glog.V(1).Infof("PCL command group: %q", buf)
		gs, err := splitGroup(buf[1:]) // skip *
		if err != nil {
			return pos, fmt.Errorf("can't split group %q: %w", buf, err)
		}

		if buf[0] == '%' {
			glog.V(1).Infof("UEL: %q", buf)
			break
		}

		gs = gs[1:]
		for _, g := range gs {
			switch g.c {
			case 'S':
				glog.V(1).Infof("set raster width: %v", g.val)
				s.width = uint(g.val)
			case 'T':
				glog.V(1).Infof("set raster height: %v", g.val)
				s.height = uint(g.val)
			case 'X':
				glog.V(1).Infof("set raster X offset: %v", g.val)
				s.x = uint(g.val)
			case 'Y':
				if g.sign == '+' {
					glog.V(1).Infof("set segment #%v, reset Y", g.val)
					s.segment = uint(g.val)
					s.y = 0
				} else {
					glog.V(1).Infof("set raster Y offset: %v", g.val)
					s.y = uint(g.val)
				}
			case 'V', 'W':
				by := "plane"
				if g.c == 'W' {
					by = "block"
				}
				s.pad = (g.c == 'V') // Only pad by-plane data
				glog.V(1).Infof("transfer %d bytes raster data by %s", g.val, by)
				if s.data != nil {
					return pos, fmt.Errorf("already have %d bytes of data", len(s.data))
				}
				buf := make([]byte, uint(g.val))
				if err := readExact(r, buf); err != nil {
					return pos, fmt.Errorf("can't read %d bytes from buffer: %w", g.val, err)
				}
				pos += uint(g.val)
				s.data = buf

			case 'M':
				glog.V(1).Infof("set compression method %d", g.val)
				s.compression = uint(g.val)

			case 'A':
				glog.V(1).Infof("start raster graphics")

			case 'C':
				glog.V(1).Infof("end raster graphics")

			default:
				return pos, fmt.Errorf("unknown command %q", g.c)
			}
		}

	case cmd == 'E':
		glog.V(1).Infof("Device reset")

	default:
		glog.Warningf("Unknown PCL command %q", cmd)
	}

	return pos, nil
}

func decompressTIFF(r *bytes.Reader, b map[uint]uint, inpos uint, outpos *uint) ([]byte, error) {
	var ret []byte
	for r.Len() > 0 {
		ctl, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("can't read control byte: %w", err)
		}
		inpos += 1
		c := int8(ctl)
		glog.V(1).Infof("c: %d", c)
		if c == -128 {
			// NOP
			continue
		}

		if c < 0 {
			repc := -c
			repb, err := r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("can't read repeated data byte: %w", err)
			}
			for i := int8(0); i <= repc; i++ {
				ret = append(ret, repb)
				b[*outpos] = inpos
				*outpos += 1
			}
			inpos += 1
			continue
		}

		ct := uint(c) + 1
		lit := make([]byte, ct)
		if err := readExact(r, lit); err != nil {
			return nil, fmt.Errorf("can't read %d literal bytes: %w", ct, err)
		}

		for i := uint(0); i < ct; i++ {
			b[*outpos] = inpos
			*outpos += 1
			inpos += 1
		}

		glog.V(1).Infof("appending %d literal bytes: % 02X", ct, lit)
		ret = append(ret, lit...)
	}

	return ret, nil
}

func decompressDeltaRow(r *bytes.Reader, seed []byte, b map[uint]uint, inpos uint, outpos *uint) ([]byte, error) {
	var ret []byte
	for r.Len() > 0 {
		ctl, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("can't read control byte: %w", err)
		}

		ct := (ctl >> 5) + 1
		off := ctl & 0x1f
		glog.V(1).Infof("first offset: %v", off)
		for i := uint8(0); i < off; i++ {
			glog.V(1).Infof("pad with %x from old buffer", seed[len(ret)])
			ret = append(ret, seed[len(ret)])
			b[*outpos] = inpos
			*outpos += 1
		}
		inpos += 1

		if off == 31 {
			for {
				var err error
				off, err = r.ReadByte()
				if err != nil {
					return nil, fmt.Errorf("can't read offset byte: %w", err)
				}
				glog.V(1).Infof("another offset: %v", off)
				for i := uint8(0); i < off; i++ {
					glog.V(1).Infof("pad with %x from old buffer", seed[len(ret)])
					ret = append(ret, seed[len(ret)])
					b[*outpos] = inpos
					*outpos += 1
				}
				inpos += 1
				if off == 255 {
					break
				}
			}
		}
		glog.V(1).Infof("copying %d bytes to offset %d", ct, len(ret))
		oldpos := len(ret)
		for i := uint8(0); i < ct; i++ {
			bt, err := r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("can't read byte to copy: %w", err)
			}
			ret = append(ret, bt)
			b[*outpos] = inpos
			*outpos += 1
		}
		inpos += 1
		glog.V(1).Infof("  copied: %q", ret[oldpos:])
	}
	return ret, nil
}

func decompress(data []byte, method uint, seed []byte, b map[uint]uint, inpos uint, outpos *uint) ([]byte, error) {
	cms := []string{"None", "RLE", "TIFF", "Delta row", "Reserved", "Adaptive"}

	var ret []byte
	switch method {
	case 0:
		// Unencoded
		ret = data
		for i := 0; i < len(ret); i++ {
			b[*outpos] = inpos
			*outpos += 1
			inpos += 1
		}

	case 2:
		// TIFF
		var err error
		ret, err = decompressTIFF(bytes.NewReader(data), b, inpos, outpos)
		if err != nil {
			return nil, fmt.Errorf("can't decompress TIFF: %w", err)
		}

	case 3:
		// Delta Row
		var err error
		ret, err = decompressDeltaRow(bytes.NewReader(data), seed, b, inpos, outpos)
		if err != nil {
			return nil, fmt.Errorf("can't decompress Delta row: %w", err)
		}

	default:
		m := fmt.Sprintf("Unknown (%d)", method)
		if method <= uint(len(cms)) {
			m = cms[method]
		}
		return nil, fmt.Errorf("Unsupported compression method %s", m)
	}

	glog.Infof("Decompressed %d %s bytes to %d", len(data), cms[method], len(ret))
	return ret, nil
}

func maybeWriteIntermediate(data []byte, suffix string) error {
	prefix := *intermediatesPrefix
	if prefix == "" {
		return nil
	}

	filename := fmt.Sprintf("%s.%s", prefix, suffix)
	if err := os.WriteFile(filename, data, 0666); err != nil {
		return err
	}

	glog.Infof("Wrote %d bytes to %v", len(data), filename)
	return nil
}

func getFlasherPayload(data []byte, b map[uint]uint) ([]byte, error) {
	glog.Infof("Extracting flasher and flash image")
	r := bufio.NewReader(bytes.NewReader(data))
	var flasher []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("can't read s-record line: %w", err)
		}
		flasher = append(flasher, line...)
		if line[0] == 'P' {
			break
		}
	}

	if err := maybeWriteIntermediate(flasher, "flasher.srec"); err != nil {
		return nil, fmt.Errorf("can't write flasher output file: %w", err)
	}

	var binsrec, srec []byte
	pos := uint(len(flasher))
	line := 0
	for r.Size() > 0 {
		line += 1
		t, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("can't read type from binary s-record: %w", err)
		}
		pos += 1
		glog.V(2).Infof("L%d: at offset 0x%x (%d), type: %02X", line, pos, pos, t)
		binsrec = append(binsrec, t)
		srec = append(srec, fmt.Sprintf("S%c", t)...)

		l, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("can't read length from binary s-record: %w", err)
		}
		pos += 1
		csum := uint16(l)
		glog.V(2).Infof("  length: %02X", l)
		binsrec = append(binsrec, l)
		srec = append(srec, fmt.Sprintf("%02X", l)...)

		data := make([]byte, l)
		if err := readExact(r, data); err != nil {
			return nil, fmt.Errorf("can't read binary s-record data: %w", err)
		}
		if len(data) > 0 {
			for _, d := range data[:len(data)-1] {
				csum += uint16(d)
			}
			csum = (csum & 0xff) ^ 0xff
			got := data[len(data)-1]
			if byte(csum) != got {
				for i := uint(0); i < uint(l); i++ {
					glog.V(1).Infof("[0x%02x = %02X] output offset 0x%x (0x%x @ payload), source at 0x%x", i, data[i], pos+i, pos-uint(len(flasher))+i, b[pos+i])
				}
				glog.V(1).Infof("data with checksum: % 02X", data)
				return nil, fmt.Errorf("checksum mismatch, got: %02X, want: %02X", data[len(data)-1], csum)
			}
		}
		srec = append(srec, fmt.Sprintf("%02X", data)...)
		srec = append(srec, '\n')
		binsrec = append(binsrec, data...)
		pos += uint(l)

	}

	if err := maybeWriteIntermediate(binsrec, "flasher_payload.bin"); err != nil {
		return nil, fmt.Errorf("can't write binary s-record output file: %w", err)
	}
	if err := maybeWriteIntermediate(srec, "flasher_payload.srec"); err != nil {
		return nil, fmt.Errorf("can't write ascii s-record output file: %w", err)
	}

	return srec, nil
}

func pcl2flash(data []byte) ([]byte, error) {
	glog.Info("Decompressing PCL")
	var inpos, seg0pos uint
	segments := make(map[uint][]byte)
	b := make(map[uint]uint) // output offset -> input offset
	s := &rasterState{}
	r := bufio.NewReader(bytes.NewReader(data))
	for r.Size() > 0 {
		text, err := r.ReadBytes('\x1b')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error reading from input buffer: %w", err)
		}

		inpos += uint(len(text))
		text = text[:len(text)-1] // strip ESC
		if len(text) > 0 {
			glog.V(1).Infof("text: %q", text)
		}

		n, err := readPCL(r, s)
		if err != nil {
			return nil, fmt.Errorf("can't parse PCL: %w", err)
		}

		if s.data != nil {
			data, err := decompress(s.data, s.compression, s.seed, b, inpos, &seg0pos)
			if err != nil {
				return nil, fmt.Errorf("can't decompress data: %w", err)
			}
			if s.pad {
				for len(data) < int(s.width) {
					if s.compression == 3 {
						glog.V(1).Infof("pad seed %x because len(data) = %d and s.width = %d", s.seed[len(data)], len(data), int(s.width))
						data = append(data, s.seed[len(data)])
					} else {
						glog.V(1).Infof("pad zero because len(data) = %d and s.width = %d", s.seed[len(data)], len(data), int(s.width))
						data = append(data, 0)
					}
				}
			}
			glog.V(2).Infof("received data: %q", data)
			glog.V(1).Infof("received %d bytes of data, inflated to %d", len(s.data), len(data))
			if glog.V(1) && s.segment == 0 {
				glog.Infof("at input offset 0x%x", inpos)
			}
			segments[s.segment] = append(segments[s.segment], data...)
			s.seed = data
			s.data = nil
		}
		inpos += n
	}

	for i, data := range segments {
		if err := maybeWriteIntermediate(data, fmt.Sprintf("pclseg%d.bin", i)); err != nil {
			return nil, fmt.Errorf("can't write decoded PCL segment %d: %w", err)
		}
	}

	seg0, ok := segments[0]
	if !ok {
		return nil, errors.New("no segment 0 found")
	}

	payload, err := getFlasherPayload(seg0, b)
	if err != nil {
		return nil, fmt.Errorf("can't extract flasher payload from PCL segment 0: %w", err)
	}

	flashSegs, err := unsrec(payload)
	if err != nil {
		return nil, fmt.Errorf("can't convert flasher payload s-record to binary: %w", err)
	}

	if len(flashSegs) != 1 {
		return nil, errors.New("flasher payload has not exactly one s-record segment")
	}

	for addr, data := range flashSegs {
		glog.Infof("Flash is at 0x%08x", addr)
		if err := maybeWriteIntermediate(data, fmt.Sprintf("flash.%08x.bin", addr)); err != nil {
			return nil, fmt.Errorf("can't write flash contents: %w", err)
		}
		return data, nil
	}

	return nil, errors.New("unreachable")
}

func parseBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd number of bytes")
	}
	ret := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		ret = append(ret, byte(b))
	}
	return ret, nil
}

func unsrec(data []byte) (map[uint64][]byte, error) {
	sc := bufio.NewScanner(bytes.NewBuffer(data))
	ret := make(map[uint64][]byte)
	var lastAddr, blockAddr uint64
	lineno := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		if len(line) < 6 {
			return nil, fmt.Errorf("line %d is too short", lineno)
		}
		if line[0] != 'S' {
			return nil, fmt.Errorf("line %d does not start with 'S'", lineno)
		}
		line = line[1 : len(line)-2] // strip leading S and trailing checksum
		t := line[0]
		line = line[3:] // strip type and length
		glog.V(2).Infof("line: %q", line)
		switch t {
		case '0':
			addr, err := strconv.ParseUint(line[0:4], 16, 16)
			if err != nil {
				return nil, fmt.Errorf("can't parse address in line %d: %w", lineno, err)
			}

			data, err := parseBytes(line[4:])
			if err != nil {
				return nil, fmt.Errorf("can't parse data in line %d: %w", lineno, err)
			}

			glog.V(1).Infof("header at addr %04x: %q", addr, string(data))

		case '3':
			addr, err := strconv.ParseUint(line[0:8], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("can't parse address in line %d: %w", lineno, err)
			}

			data, err := parseBytes(line[8:])
			if err != nil {
				return nil, fmt.Errorf("can't parse data in line %d: %w", lineno, err)
			}

			if addr != lastAddr {
				glog.V(1).Infof("new block at %08x", addr)
				blockAddr = addr
				lastAddr = addr
			}

			ret[blockAddr] = append(ret[blockAddr], data...)
			lastAddr += uint64(len(data))

		case '7':
			if len(line) != 8 {
				return nil, fmt.Errorf("start address not 8 hex characters at line %d", lineno)
			}
			addr, err := strconv.ParseUint(line, 16, 32)
			if err != nil {
				return nil, fmt.Errorf("can't parse start address: %v", err)
			}
			glog.V(1).Infof("start address: %08x", addr)

		default:
			return nil, fmt.Errorf("unknown S-record type %c", t)
		}
	}

	return ret, nil
}

func removeOOB(data []byte) ([]byte, error) {
	pageSize, oobSize := *flashPageSize, *flashOOBsize
	if len(data)%(pageSize+oobSize) != 0 {
		return nil, fmt.Errorf("data (len = 0x%x) is not a multiple of 0x%x+0x%x", len(data), pageSize, oobSize)
	}

	ret := make([]byte, 0, len(data)/(pageSize+oobSize)*pageSize)
	for i := 0; i < len(data); i += pageSize + oobSize {
		ret = append(ret, data[i:i+pageSize]...)
	}

	return ret, nil
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

type sectionInfo struct {
	Name  string `json:"name"`
	Start uint32 `json:"start_address"`
	Size  uint32 `json:"size"`
	Flags uint32 `json:"flags"`
	Dest  uint32 `json:"dest_address,omitempty"`
}

func (si *sectionInfo) String() string {
	dst := ""
	if si.Dest != 0 {
		dst = fmt.Sprintf(" => 0x%08x", si.Dest)
	}
	return fmt.Sprintf("section %q [0x%08x-0x%08x] flags 0x%x%s", si.Name, si.Start, si.Start+si.Size-1, si.Flags, dst)
}

type loadInfo struct {
	Filename        string `json:"filename,omitempty"`
	AllZeros        bool   `json:"all_zeros"`
	FlashSourceAddr uint32 `json:"flash_source_start"`
	FlashSourceLen  uint32 `json:"flash_source_len"`
}

type memorySegment struct {
	Start       uint32       `json:"start_address"`
	Data        []byte       `json:"-"`
	SectionInfo *sectionInfo `json:"section_info"`
	LoadInfo    loadInfo     `json:"load_info"`
}

func (s *memorySegment) size() uint32 {
	return uint32(len(s.Data))
}

func (s *memorySegment) hasAddr(addr uint32) bool {
	return addr >= s.Start && addr < s.Start+s.size()
}

func (s *memorySegment) String() string {
	if s.SectionInfo != nil {
		return s.SectionInfo.String()
	}
	return fmt.Sprintf("[0x%08x-0x%08x]", s.Start, s.Start+s.size()-1)
}

type memory struct {
	S []*memorySegment `json:"segments"`
}

func (m *memory) segmentFor(addr uint32) (*memorySegment, bool) {
	for _, s := range m.S {
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
		high = ss.Start + ss.size() + 1
	} else {
		es, ok := m.segmentFor(high - 1)
		if !ok {
			return nil, fmt.Errorf("no segment for 0x%08x found", high-1)
		}

		if ss != es {
			return nil, fmt.Errorf("memory[0x%08x:0x%08x] not contiguous, start segment: %v, end segment: %v", ss, es)
		}
	}

	lowIdx, highIdx := low-ss.Start, high-ss.Start
	return ss.Data[lowIdx:highIdx], nil
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

func (m *memory) addSegment(start uint32, data []byte, info *sectionInfo) (*memorySegment, error) {
	ns := &memorySegment{Start: start, Data: data, SectionInfo: info}
	s, ok := m.segmentFor(ns.Start)
	if !ok {
		s, ok = m.segmentFor(ns.Start + ns.size() - 1)
	}
	if ok {
		return nil, fmt.Errorf("segment %v overlaps with existing segment %v", ns, s)
	}

	m.S = append(m.S, ns)
	return ns, nil
}

func (m *memory) memset(addr, val, count uint32, si *sectionInfo) error {
	glog.V(1).Infof("memset(0x%x, %d, %d)", addr, val, count)
	if count != si.Size {
		return fmt.Errorf("requested to memset %d bytes, but segment has %d bytes", count, si.Size)
	}
	if val != 0 {
		return errors.New("can only memset to zero")
	}

	data := make([]byte, count)
	s, err := m.addSegment(addr, data, si)
	if err != nil {
		return fmt.Errorf("can't add segment: %w", err)
	}

	s.LoadInfo.AllZeros = true
	return nil
}

func (m *memory) memcpy(dst, src, count uint32, si *sectionInfo) error {
	glog.V(1).Infof("memcpy(0x%x, 0x%x, %d)", dst, src, count)
	if count != si.Size {
		return fmt.Errorf("requested to memcpy %d bytes, but segment has %d bytes", count, si.Size)
	}

	data, err := m.slice(src, src+count)
	if err != nil {
		return err
	}

	s, err := m.addSegment(dst, data, si)
	if err != nil {
		return fmt.Errorf("can't add segment: %w", err)
	}

	s.LoadInfo.FlashSourceAddr = src
	s.LoadInfo.FlashSourceLen = count
	return nil
}

func (m *memory) uncompress(dst, src, count uint32, si *sectionInfo) error {
	glog.V(1).Infof("uncompress(0x%x, 0x%x, %d)", dst, src, count)

	cdata, err := m.slice(src, src+count)
	if err != nil {
		return err
	}
	data := lzss.Decompress(cdata)
	if uint32(len(data)) != si.Size {
		return fmt.Errorf("uncompress inflated %d to %d bytes, but segment has %d bytes", count, len(data), si.Size)
	}

	_, err = m.addSegment(dst, data, si)
	return err
}

type app struct {
	Mem            *memory                 `json:"memory"`
	EntryPoint     uint32                  `json:"entry_point"`
	HeaderAddr     uint32                  `json:"header_address"`
	UnusedSections map[uint32]*sectionInfo `json:"unused_sections"`
}

func dumpApp(h *flashHeader, data []byte) (*app, error) {
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
	glog.V(1).Infof("header fields: %#v", hf)

	si := make(map[uint32]*sectionInfo)
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
		glog.V(1).Infof("sectionInfo fields: %#v", sf)

		name, err := m.cstring(sf[1])
		if err != nil {
			return nil, fmt.Errorf("can't retrieve section name: %w", err)
		}
		start := sf[2]
		if exist, ok := si[start]; ok {
			return nil, fmt.Errorf("duplicate section definition for 0x%08x, prev = %s, curr = %s", start, exist.Name, name)
		}

		size := sf[3]
		if size > 0 {
			si[start] = &sectionInfo{
				Name:  name,
				Start: start,
				Size:  size,
				Flags: sf[4],
				Dest:  sf[5],
			}
		}

		secAddr = sf[0]
	}

	flashSectInfo, ok := si[h.loadAddr]
	if !ok {
		return nil, fmt.Errorf("section for flash at 0x%08x not found", h.loadAddr)
	}
	flashSeg.SectionInfo = flashSectInfo
	delete(si, h.loadAddr)

	funcs := []struct {
		name       string
		f          func(_, _, _ uint32, _ *sectionInfo) error
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

	for addr, s := range si {
		glog.Infof("Unused section 0x%08x: %v", addr, s)
	}

	return &app{
		Mem:            m,
		EntryPoint:     hf[13],
		HeaderAddr:     hdrAddr,
		UnusedSections: si,
	}, nil
}

func dumpFlash(data []byte) error {
	glog.Info("Dumping flash contents...")
	data, err := removeOOB(data)
	if err != nil {
		return fmt.Errorf("can't remove OOB data: %w", err)
	}

	if err = maybeWriteIntermediate(data, "flash.nooob.bin"); err != nil {
		return fmt.Errorf("can't write flash no-oob contents: %w", err)
	}

	header, err := parseHeader(data)
	if err != nil {
		return fmt.Errorf("can't parse header: %v", err)
	}

	glog.Infof("Flash header: %#v", header)

	pageSize := uint32(*flashPageSize)
	if header.pageSize1 != pageSize {
		return fmt.Errorf("header.PageSize1 (0x%x) != pageSize (0x%x)", header.pageSize1, pageSize)
	}

	bmp := data[pageSize : pageSize+header.bmpSize]
	if err := os.WriteFile(*outPrefix+".boot.bmp", bmp, 0666); err != nil {
		return fmt.Errorf("can't write bitmap: %w", err)
	}

	codeStart := pageSize + header.bmpSize
	if rem := codeStart % pageSize; rem != 0 {
		codeStart += pageSize - rem
	}
	glog.Infof("Code start at 0x%x", codeStart)

	code := data[codeStart : codeStart+header.loadSize]
	if err := maybeWriteIntermediate(code, "flash.code.bin"); err != nil {
		return fmt.Errorf("can't write code: %w", err)
	}

	if rem := len(data) - int(codeStart+header.loadSize); rem >= int(pageSize) {
		return fmt.Errorf("remaining data (len = 0x%x) after code >= pageSize (0x%x)", rem, pageSize)
	}

	app, err := dumpApp(header, code)
	if err != nil {
		return fmt.Errorf("can't dump app: %w", err)
	}

	for _, s := range app.Mem.S {
		fn := fmt.Sprintf("%s.0x%08x%s.bin", *outPrefix, s.Start, s.SectionInfo.Name)
		if err := os.WriteFile(fn, s.Data, 0666); err != nil {
			return fmt.Errorf("can't write segment 0x%08x: %w", s.Start, err)
		}

		glog.Infof("Wrote %v (%d bytes) to %v", s, s.size(), fn)
		s.LoadInfo.Filename = filepath.Base(fn)
	}

	j, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return fmt.Errorf("can't marshal app to JSON: %w", err)
	}
	jfn := *outPrefix + ".app.json"
	if err := os.WriteFile(jfn, j, 0666); err != nil {
		return fmt.Errorf("can't write app JSON: %w", err)
	}
	glog.Infof("Wrote metadata to %v", jfn)

	return nil
}
func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	if *inFile == "" || *outPrefix == "" {
		if len(os.Args) < 3 {
			glog.Exitf("Both -input_filename and -output_prefix must be set.")
		}
		*inFile = os.Args[1]
		*outPrefix = os.Args[2]
	}

	if *intermediatesPrefix == "" && len(os.Args) == 4 {
		*intermediatesPrefix = os.Args[3]
	}

	data, err := os.ReadFile(*inFile)
	if err != nil {
		glog.Exitf("Can't read input file: %v", err)
	}

	glog.Infof("Read %d bytes from %s", len(data), *inFile)

	payload, err := pcl2flash(data)
	if err != nil {
		glog.Exitf("Can't extract flash image from PCL: %v", err)
	}
	glog.Infof("Extracted %d payload bytes from PCL", len(payload))

	if err = dumpFlash(payload); err != nil {
		glog.Exitf("Can't dump flash image: %v", err)
	}
}
