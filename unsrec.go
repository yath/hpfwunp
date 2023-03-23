package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
)

var inFile = flag.String("input_filename", "out.data.srec", "input filename")
var outPrefix = flag.String("output_prefix", "srec.out", "output filename prefix")

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

func main() {
	flag.Parse()

	f, err := os.Open(*inFile)
	if err != nil {
		log.Fatal(err)
	}
	sc := bufio.NewScanner(f)

	var outf *os.File
	defer func() {
		if outf != nil {
			if err := outf.Close(); err != nil {
				log.Fatalf("can't close output file %v: %v", outf.Name(), err)
			}
		}
	}()

	var lastAddr uint64
	lineno := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		if len(line) < 6 {
			log.Fatalf("line %d is too short", lineno)
		}
		if line[0] != 'S' {
			log.Fatalf("line %d does not start with 'S'", lineno)
		}
		line = line[1 : len(line)-2] // strip leading S and trailing checksum
		t := line[0]
		line = line[3:] // strip type and length
		//log.Printf("line: %q", line)
		switch t {
		case '0':
			addr, err := strconv.ParseUint(line[0:4], 16, 16)
			if err != nil {
				log.Fatalf("can't parse address in line %d: %v", lineno, err)
			}

			data, err := parseBytes(line[4:])
			if err != nil {
				log.Fatalf("can't parse data in line %d: %v", lineno, err)
			}

			log.Printf("header at addr %04x: %q", addr, string(data))

		case '3':
			addr, err := strconv.ParseUint(line[0:8], 16, 32)
			if err != nil {
				log.Fatalf("can't parse address in line %d: %v", lineno, err)
			}

			data, err := parseBytes(line[8:])
			if err != nil {
				log.Fatalf("can't parse data in line %d: %v", lineno, err)
			}

			if addr != lastAddr {
				log.Printf("new block at %08x", addr)
				if outf != nil {
					if err := outf.Close(); err != nil {
						log.Fatalf("can't close output file %v: %v", outf.Name(), err)
					}
				}

				var err error
				outf, err = os.Create(fmt.Sprintf("%s.%08x.bin", *outPrefix, addr))
				if err != nil {
					log.Fatalf("can't create output file: %v", err)
				}
				lastAddr = addr
			}

			if _, err := outf.Write(data); err != nil {
				log.Fatalf("can't write to output file %v: %v", outf.Name(), err)
			}
			lastAddr += uint64(len(data))

		case '7':
			if len(line) != 8 {
				log.Fatalf("start address not 8 hex characters at line %d", lineno)
			}
			addr, err := strconv.ParseUint(line, 16, 32)
			if err != nil {
				log.Fatalf("can't parse start address: %v", err)
			}
			log.Printf("start address: %08x", addr)

		default:
			log.Fatalf("unknown S-record type %c", t)
		}
	}
}
