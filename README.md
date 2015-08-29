# identix
Python utility which will recursively scan one or more given directories for duplicate files. Files to consider for checking can optionally be filtered based on:
- One or more glob filespecs.
- Minimum file size.

## What is a duplicate?
Files are considered duplicate based on their identical binary representation:
- Files as scanned are grouped by their file size to quickly rule out non-duplicates.
- Groups of files sharing the same file size then have their MD5 checksums calculated, those that match are duplicates.

## Usage

```
usage: identix.py [-h] [--include [INCLUDE [INCLUDE ...]]]
                  [--min-size MIN_SIZE] [--progress]
                  [--report-file REPORT_FILE]
                  scandir [scandir ...]

Recursively scan one or more directories for duplicate files.

positional arguments:
  scandir               list of directories to scan for duplicates

optional arguments:
  -h, --help            show this help message and exit
  --include [INCLUDE [INCLUDE ...]]
                        glob filespec(s) to include in file scan, if omitted
                        all files considered
  --min-size MIN_SIZE   minimum file size to be considered
  --progress            show progress during file diffing
  --report-file REPORT_FILE
                        output duplicate report to file, rather than screen
```

Notes:
- `--include` glob filespecs format, for the *filename only* such as `*.jpg`, `image*.png`, etc.
- Omitting `--report-file` output file will display duplicate file results directly to the console.
