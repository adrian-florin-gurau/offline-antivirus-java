# Offline Antivirus in Java 🛡️

A Java program that represents an offline Antivirus which verifies the integrity of files on your system.  
It can detect **corrupted** and **new** files based on their `HmacSHA256`, and can also create **reports** for each examination session.

## Features

- Offline file integrity verification
- HMAC-SHA256 cryptographic hashing
- Recursive directory traversal
- Optional depth-limited scanning
- Detection of:
  - OK (unchanged) files
  - CORRUPTED (modified) files
  - NEW files
- Automatic report generation
- Colored terminal output using ANSI escape codes
- Timestamped report and HMAC files

## Requirements

- Java 8 or higher
- Read permissions for the scanned directories
- Terminal with ANSI color support  
  (ANSI support is enabled automatically on Windows)

## Repository Structure

offline-antivirus-java/ <br/>
├── OfflineAntivirus.java <br/>
└── README.md <br/>

## Compilation

```powershell
javac OfflineAntivirus.java
```

## Execution

```powershell
java OfflineAntivirus <scan|check> <secret> <rootPath> <hmacFile> [<noOfLevelsDeep>]
```

## Arguments

| Argument | Description | Position | Mandatory |
|----------|-------------|----------|-----------|
| scan | Generates a new HMAC database | 1 | yes (or check) |
| check | Verifies file integrity using an existing HMAC file | 1 | yes (or scan) |
| secret | HMAC secret key (minimum 8 characters, 32 recommended) | 2 | yes |
| rootPath | Root directory to scan | 3 | yes |
| hmacFile | Text file (.txt) used to store or read HMACs | 4 | yes |
| noOfLevelsDeep | Optional maximum directory depth (natural number > 0) | 5 | no |

## Scan Mode

Creates or overwrites the specified HMAC file and computes the HMAC for each readable file.

```powershell
java OfflineAntivirus scan mySecret123 /home/user/data hashes.txt
```

If the HMAC file already exists, the user is prompted for confirmation before overwriting.

Each scanned file is stored as:

```
<absolute_file_path>
<base64_encoded_hmac>
```

## Check Mode

Verifies the integrity of current files against a previously generated HMAC file.

```powershell
java OfflineAntivirus check mySecret123 /home/user/data hashes.txt
```

Detected file statuses:

- **OK** – file unchanged
- **CORRUPTED** – file contents modified
- **NEW** – file not present in the HMAC database

## Report Generation

During check mode, a report file is generated automatically.

Report filename format:

```report_YYYY-MM-DD_HH-mm-ss_GMT±XXXX_<Zone>.txt```

Each report line has the format:

```<STATUS>,<FILE_PATH>,<CURRENT_HMAC>```

Example:

```[OK],/home/user/data/file.txt,AbCdEfGh...```

## Console Output Colors

- **Green** – OK files
- **Yellow** – Corrupted files
- **Blue** – New files
- **Red** – Errors
- **Purple** – Information and summary

## Exit Codes

| Code | Meaning |
|----|--------|
| 0 | Successful execution |
| 1 | Invalid number of arguments |
| 2 | Invalid secret |
| 3 | Invalid mode |
| 4 | Invalid root path |
| 5 | HMAC file does not exist |
| 6 | HMAC path is not a file |
| 7 | Invalid depth value |
| 8 | Invalid HMAC file format |
| 9 | User aborted operation |

## Security Details

- Cryptographic algorithm: HmacSHA256
- Files are read using buffered streams (4 KB blocks)
- The secret key is never stored on disk
- Only readable files and directories are processed

## Important Notes

- The HMAC file itself is always detected as NEW during check mode
- Hidden files are included if readable
- Symbolic links are treated as regular files if readable

## License

This project is intended for educational and academic purposes only.  
No warranty is provided. Use at your own risk.

## Author

Adrian-Florin Gurău  
