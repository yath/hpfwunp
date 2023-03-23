package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

var inFile = flag.String("input_filename", "FDP1CN1416AR_nbx_signed.ful", "name of input file")
var intermediatesPrefix = flag.String("intermediates_prefix", "", "if nonempty, writes intermediate files with this prefix")

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
		log.Printf("PCL command group: %q", buf)
		gs, err := splitGroup(buf[1:]) // skip *
		if err != nil {
			return pos, fmt.Errorf("can't split group %q: %w", buf, err)
		}

		if buf[0] == '%' {
			log.Printf("UEL: %q", buf)
			break
		}

		gs = gs[1:]
		for _, g := range gs {
			switch g.c {
			case 'S':
				log.Printf("set raster width: %v", g.val)
				s.width = uint(g.val)
			case 'T':
				log.Printf("set raster height: %v", g.val)
				s.height = uint(g.val)
			case 'X':
				log.Printf("set raster X offset: %v", g.val)
				s.x = uint(g.val)
			case 'Y':
				if g.sign == '+' {
					log.Printf("set segment #%v, reset Y", g.val)
					s.segment = uint(g.val)
					s.y = 0
				} else {
					log.Printf("set raster Y offset: %v", g.val)
					s.y = uint(g.val)
				}
			case 'V', 'W':
				by := "plane"
				if g.c == 'W' {
					by = "block"
				}
				s.pad = (g.c == 'V') // Only pad by-plane data
				log.Printf("transfer %d bytes raster data by %s", g.val, by)
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
				log.Printf("set compression method %d", g.val)
				s.compression = uint(g.val)

			case 'A':
				log.Printf("start raster graphics")

			case 'C':
				log.Printf("end raster graphics")

			default:
				return pos, fmt.Errorf("unknown command %q", g.c)
			}
		}

	case cmd == 'E':
		log.Printf("Device reset")

	default:
		log.Printf("Unknown PCL command %q", cmd)
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
		log.Printf("c: %d", c)
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

		log.Printf("appending %d literal bytes: % 02X", ct, lit)
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
		log.Printf("first offset: %v", off)
		for i := uint8(0); i < off; i++ {
			log.Printf("pad with %x from old buffer", seed[len(ret)])
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
				log.Printf("another offset: %v", off)
				for i := uint8(0); i < off; i++ {
					log.Printf("pad with %x from old buffer", seed[len(ret)])
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
		log.Printf("copying %d bytes to offset %d", ct, len(ret))
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
		log.Printf("  copied: %q", ret[oldpos:])
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

	log.Printf("Decompressed %d %s bytes to %d", len(data), cms[method], len(ret))
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

	log.Printf("Wrote %d bytes to %v", len(data), filename)
	return nil
}

func getFlasherPayload(data []byte, b map[uint]uint) ([]byte, error) {
	log.Printf("Extracting flasher and flash image")
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
		//log.Printf("L%d: at offset 0x%x (%d), type: %02X", line, off, off, t)
		binsrec = append(binsrec, t)
		srec = append(srec, fmt.Sprintf("S%c", t)...)

		l, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("can't read length from binary s-record: %w", err)
		}
		pos += 1
		csum := uint16(l)
		//log.Printf("  length: %02X", l)
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
					log.Printf("[0x%02x = %02X] output offset 0x%x (0x%x @ payload), source at 0x%x", i, data[i], pos+i, pos-uint(len(flasher))+i, b[pos+i])
				}
				log.Printf("data with checksum: % 02X", data)
				return nil, fmt.Errorf("checksum mismatch, got: %02X, want: %02X", data[len(data)-1], csum)
				//data[len(data)-1] = byte(csum)
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
			log.Printf("text: %q", text)
		}

		n, err := readPCL(r, s)
		if err != nil {
			log.Fatalf("can't parse PCL: %v", err)
		}

		if s.data != nil {
			data, err := decompress(s.data, s.compression, s.seed, b, inpos, &seg0pos)
			if err != nil {
				log.Fatalf("can't decompress data: %v", err)
			}
			if s.pad {
				for len(data) < int(s.width) {
					if s.compression == 3 {
						log.Printf("pad seed %x because len(data) = %d and s.width = %d", s.seed[len(data)], len(data), int(s.width))
						data = append(data, s.seed[len(data)])
					} else {
						log.Printf("pad zero because len(data) = %d and s.width = %d", s.seed[len(data)], len(data), int(s.width))
						data = append(data, 0)
					}
				}
			}
			//log.Printf("received data: %q", data)
			log.Printf("received %d bytes of data, inflated to %d", len(s.data), len(data))
			if s.segment == 0 {
				log.Printf("at input offset 0x%x", inpos)
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
		log.Printf("flash at 0x%08x", addr)
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
		//log.Printf("line: %q", line)
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

			log.Printf("header at addr %04x: %q", addr, string(data))

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
				log.Printf("new block at %08x", addr)
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
			log.Printf("start address: %08x", addr)

		default:
			return nil, fmt.Errorf("unknown S-record type %c", t)
		}
	}

	return ret, nil
}

func main() {
	flag.Parse()

	data, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Read %d bytes from %s", len(data), *inFile)

	payload, err := pcl2flash(data)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("flash len: %d", len(payload))

}
