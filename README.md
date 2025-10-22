# bflip

generate multiple unique hashes of a windows kernel driver by randomizing the pe checksum field while preserving code signing and functionality.

## what it does

- finds the pe checksum field in a .sys driver file
- generates random uint32 values to write to the checksum
- creates completely different sha256 hashes for each file
- keeps the authenticode signature valid
- driver loads and runs exactly the same
- can generate up to 2^32 (4,294,967,296) unique variations

## why this works

windows authenticode signatures don't cover the pe checksum field. it's explicitly excluded from the hash calculation, so you can flip bits there without invalidating the signature.

this means:
- original driver: `abc123...` (blocked by hash-based detections)
- flipped driver: `def456...` (same signature, bypasses hash iocs)
- both load normally with secure boot + hvci enabled

## usage

### generate a single file
```bash
bflip.exe -f vulnerable_driver.sys
```

### generate multiple files
```bash
bflip.exe -f vulnerable_driver.sys -n 10
```

### example output
```
$ ./b.exe -f wsftprm.sys -n 1
processing file: wsftprm.sys
[+] original file hash: ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8
[+] original file size: 38816 bytes
[+] original checksum: 0x0000C475
[+] checksum offset: 328 (0x148)

generating 1 file(s)...

[1/1] checksum: 0xF44CACAC | hash: ed0f8a4ec047bdee... | signature: valid

============================================================
generation summary
============================================================
original file:       wsftprm.sys
original hash:       ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8
original checksum:   0x0000C475

files generated:     1
unique hashes:       1
valid signatures:    1
invalid signatures:  0
success rate:        100.00%

------------------------------------------------------------
theoretical maximum: 2^32 = 4294967296 possible variations
collision space:     0.00000002% explored

------------------------------------------------------------
[+] you may reuse these vulnerable drivers if original hash gets blocked
============================================================
```

## use cases

- **byovd techniques**: reuse vulnerable drivers with new hashes
- **edr testing**: bypass hash-based driver blocklists
- **ioc research**: demonstrate limitations of hash-only detections
- **red team ops**: evade signature-based driver blocks

## requirements

- windows (powershell for signature verification)
- signed kernel driver (.sys file)

## build
```bash
go build main.go
```

## notes

- only works on signed drivers (unsigned drivers don't benefit from this)
- the pe checksum field is never validated by windows for driver loading
- modified drivers maintain identical functionality and valid signatures
- test mode not required - works with secure boot enabled
- each file gets a random uint32 checksum, producing unique hashes
- theoretical maximum of 2^32 (4,294,967,296) unique variations per driver
- output files are named with timestamp and sequential numbering

## disclaimer

this tool is for security research and authorized testing only. don't use it to bypass security controls you don't own.

---

*made with <3 for understanding authenticode quirks*
>inspired by Silver Fox and thehackernews https://thehackernews.com/2025/09/silver-fox-exploits-microsoft-signed.html
