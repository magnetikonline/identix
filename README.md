# identix
Python utility which will recursively scan one or more given directories for duplicate files.

- [What is a duplicate?](#what-is-a-duplicate)
- [Usage](#usage)
- [Examples](#examples)

## What is a duplicate?
Files are considered duplicate based on their identical binary representation:
- Files are scanned and grouped by file size to quickly rule out non-duplicates.
- Grouped files then have SHA-1 hashes calculated - those that match are duplicates.

Files to consider can optionally be filtered based on:
- One or more glob filespecs.
- Minimum file size.

## Usage

```
usage: identix.py [-h] [--include [INCLUDE [INCLUDE ...]]]
                  [--min-size MIN_SIZE] [--progress]
                  [--report-file REPORT_FILE]
                  [--report-file-format {text,JSON}]
                  scandir [scandir ...]

Recursively scan one or more directories for duplicate files.

positional arguments:
  scandir               source directory/directories for scanning

optional arguments:
  -h, --help            show this help message and exit
  --include [INCLUDE [INCLUDE ...]]
                        glob filespec(s) to include in scan, if omitted all
                        files are considered
  --min-size MIN_SIZE   minimum filesize considered
  --progress            show progress during file diffing
  --report-file REPORT_FILE
                        send duplicate report to file, rather than console
  --report-file-format {text,JSON}
                        format of duplicate report file
```

Notes:
- The `--include` argument evaluates *filename only*, so expects globs such as `*.jpg` or `image*.png`.
- Omitting `--report-file` output file argument will display results directly on the console
- Option `--report-file-format` enables `--report-file` as `JSON` - format example:

	```json
	[
	  {
	    "sha-1": "xxxxx",
	    "size": 12345,
	    "fileList": ["/path/to/file","/path/to/another/file"]
	  },
	  {
	    "sha-1": "yyyyy",
	    "size": 6789,
	    "fileList": ["/path/to/yet/another/file","/one/more/file"]
	  },
	]
	```

## Examples
Scan for duplicates greater than or equal to `2048` bytes in the directories of `/dupe/path/one` and `/dupe/path/two`:

```sh
$ ./identix.py \
  --min-size 2048 \
    -- /dupe/path/one /dupe/path/two
```

Find duplicates that match file globs of `*.jpg` and `*.png` in `/my/images`, write results to `/path/to/report.txt` and display processing progress to console:

```sh
$ ./identix.py \
  --include "*.jpg" "*.png" \
  --progress \
  --report-file /path/to/report.txt \
    -- /my/images
```
