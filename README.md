# bflip

flip a single bit in a windows kernel driver's pe checksum field to generate a new file hash while preserving code signing and functionality.

## what it does

- finds the pe checksum field in a .sys driver file
- randomly flips one bit in the 4-byte checksum
- generates a completely different sha256 hash
- keeps the authenticode signature valid
- driver loads and runs exactly the same

## why this works

windows authenticode signatures don't cover the pe checksum field. it's explicitly excluded from the hash calculation, so you can flip bits there without invalidating the signature.

this means:
- original driver: `abc123...` (blocked by hash-based detections)
- flipped driver: `def456...` (same signature, bypasses hash iocs)
- both load normally with secure boot + hvci enabled

## usage
```bash
bflip.exe vulnerable_driver.sys
```

output:
```
$ ./b.exe wsftprm.sys
Processing file: wsftprm.sys
[+] original file hash: ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8
[+] original file size: 38816 bytes
[+] flipping bit 1 in checksum byte 2 (absolute offset 330)
[+] checksum field value changed: 0x0000C475 -> 0x0002C475

 bit flip completed:
[+]  target: pe checksum field
[+]  offset: 330 (0x14A)
[+]  bit: 1
[+]  original byte: 0x00
[+]  modified byte: 0x02

file saved as: wsftprm_flipped_20251021_144444.sys
original hash: ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8
modified hash: 1e843c4ef0a2a99aa3754902fad52630902220da9776366951668e15a497860d
[+] you may reuse this vulnerable driver if original hash gets blocked

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
go build bflip.go
```

## notes

- only works on signed drivers (unsigned drivers don't benefit from this)
- the pe checksum field is never validated by windows for driver loading
- flipped drivers maintain identical functionality and valid signatures
- test mode not required - works with secure boot enabled
- each run produces a different hash due to random bit selection

## disclaimer

this tool is for security research and authorized testing only. don't use it to bypass security controls you don't own.

---

*made with <3 for understanding authenticode quirks*
>inspired by Silver Fox and thehackernews [(https://thehackernews.com/2025/09/silver-fox-exploits-microsoft-signed.html)]
