#!/usr/bin/env python3

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import sys
import time
from typing import Dict, List, Set

FILE_CHUNK_MD5_SIZE = 4096
REPORT_FILE_FORMAT_TEXT = "text"
REPORT_FILE_FORMAT_JSON = "JSON"
REPORT_FILE_FORMAT_JSON_SEPARATORS = (",", ":")


class Console:
    TERMINAL_CONNECTED = sys.stdout.isatty()
    TERMINAL_SIZE_CACHE_SECONDS = 2
    CURSOR_START_LINE_CLEAR_RIGHT = "{0}{1}".format("\r", "\x1b[K")

    DOT_GAP_MIN_LENGTH = 3
    TEXT_SPLIT_MIN_LENGTH = 5

    class TERM_COLOR:
        RESET = "\x1b[0m"
        YELLOW = "\x1b[33m"

    progress_enabled = False

    _progress_active = False
    _last_term_size = (0, 0, 0)

    def _terminal_size(self):
        now_timestamp = int(time.time())

        if now_timestamp >= (
            Console._last_term_size[0] + Console.TERMINAL_SIZE_CACHE_SECONDS
        ):
            # (re-)fetch terminal dimensions
            size = shutil.get_terminal_size()
            Console._last_term_size = (now_timestamp,) + size
            return size

        # return previously stored dimensions
        return Console._last_term_size[1:]

    def _text_truncated(self, text: str, max_length: int):
        if len(text) < max_length:
            # no need for truncation
            return text

        # determine dot gap length - 5% of max length, plus two space characters
        dot_gap = int(max_length * 0.05) + 2
        if dot_gap < Console.DOT_GAP_MIN_LENGTH:
            dot_gap = Console.DOT_GAP_MIN_LENGTH

        # calculate split size - if too small just truncate and bail
        split_size = int((max_length - dot_gap) / 2)
        if split_size < Console.TEXT_SPLIT_MIN_LENGTH:
            return text[:max_length].strip()

        # return [HEAD_CHUNK ... TAIL_CHUNK]
        return "{0} {1} {2}".format(
            text[:split_size].strip(),
            +((max_length - (split_size * 2)) - 2) * ".",
            text[0 - split_size :].strip(),
        )

    def _write_flush(self, text: str):
        sys.stdout.write(text)
        sys.stdout.flush()

    def _progress_end(self):
        if not Console._progress_active:
            return

        # clean up progress line from terminal, reset foreground color
        Console._progress_active = False
        self._write_flush(
            Console.CURSOR_START_LINE_CLEAR_RIGHT + Console.TERM_COLOR.RESET
        )

    def exit_error(self, message: str):
        self._progress_end()
        print(f"Error: {message}", file=sys.stderr)
        sys.exit(1)

    def write(self, text: str = ""):
        self._progress_end()
        print(text)

    def progress(self, text: str):
        # only display if connected to terminal and enabled
        if (not Console.TERMINAL_CONNECTED) or (not Console.progress_enabled):
            return

        # fetch terminal dimensions
        max_width, _ = self._terminal_size()
        write_list = []

        if not Console._progress_active:
            # commence progress mode
            Console._progress_active = True
            write_list.append(Console.TERM_COLOR.YELLOW)

        # write progress message
        write_list.append(
            Console.CURSOR_START_LINE_CLEAR_RIGHT
            + self._text_truncated(text, max_width)
        )

        self._write_flush("".join(write_list))


def read_arguments(console: Console):
    # create argument parser
    parser = argparse.ArgumentParser(
        description="Recursively scan one or more directories for duplicate files."
    )

    parser.add_argument(
        "scandir", help="source directory/directories for scanning", nargs="+"
    )

    parser.add_argument(
        "--include",
        help="glob filespec(s) to include in scan, if omitted all files are considered",
        nargs="*",
    )

    parser.add_argument("--min-size", help="minimum filesize considered", type=int)

    parser.add_argument(
        "--progress", action="store_true", help="show progress during file diffing"
    )

    parser.add_argument(
        "--report-file", help="send duplicate report to file, rather than console"
    )

    parser.add_argument(
        "--report-file-format",
        choices=[REPORT_FILE_FORMAT_TEXT, REPORT_FILE_FORMAT_JSON],
        help="format of duplicate report file",
    )

    arg_list = parser.parse_args()

    # ensure all scan dirs exist
    scan_dir_list = arg_list.scandir
    for scan_dir in scan_dir_list:
        if not os.path.isdir(scan_dir):
            console.exit_error("Invalid directory [{0}]".format(scan_dir))

    # get canonical path of each scan dir
    scan_dir_list = list(
        map(lambda scandir: os.path.realpath(scandir), arg_list.scandir)
    )

    # ensure each given scan directory does not overlap
    for source_index in range(len(scan_dir_list)):
        for dest_index in range(source_index + 1, len(scan_dir_list)):
            if (scan_dir_list[source_index].find(scan_dir_list[dest_index]) == 0) or (
                scan_dir_list[dest_index].find(scan_dir_list[source_index]) == 0
            ):
                console.exit_error(
                    "Scan directory [{0}] overlaps with [{1}]".format(
                        scan_dir_list[source_index], scan_dir_list[dest_index]
                    )
                )

    # ensure all [--include] file globs are valid and compile to regular expressions via fnmatch
    file_include_regexp_list = set()
    if arg_list.include:
        for file_include_glob in arg_list.include:
            if not re.search(r"^[A-Za-z0-9_.*?!\-\[\]]+$", file_include_glob):
                # invalid glob
                console.exit_error(
                    "Invalid file include glob [{0}]".format(file_include_glob)
                )

            # valid - add to list as a regular expression compiled from fnmatch
            file_include_regexp_list.add(
                re.compile(fnmatch.translate(file_include_glob))
            )

    # determine minimum file size to consider
    minimum_filesize = 0
    if arg_list.min_size is not None:
        minimum_filesize = arg_list.min_size

    # the [--report-file-format] option can only be used when writing report to file
    if (arg_list.report_file is None) and (arg_list.report_file_format is not None):
        console.exit_error(
            "Argument [--report-file-format] only valid with [--report-file]"
        )

    # return arguments
    return (
        set(scan_dir_list),
        file_include_regexp_list,
        minimum_filesize,
        arg_list.progress,
        os.path.realpath(arg_list.report_file)
        if (arg_list.report_file is not None)
        else None,
        (
            False
            if (arg_list.report_file_format is None)
            else (arg_list.report_file_format == REPORT_FILE_FORMAT_JSON)
        ),
    )


def scan_dir_list_recursive(
    console: Console,
    scan_dir_list: List[str],
    file_include_regexp_list: Set[re.Pattern],
    minimum_filesize: int,
):
    # setup file match glob function
    if file_include_regexp_list:

        def is_file_glob_match(filename: str):
            # at least one file_include_regexp_list item must match the filename
            # note: using .match() here, as what's expected to be used with fnmatch.translate()
            return any(regexp.match(filename) for regexp in file_include_regexp_list)

    else:

        def is_file_glob_match(filename: str):
            # always a match if no globs defined
            return True

    # setup directory processor - called recursively for each sub-dir
    def process_file_list(
        base_dir: str,
        filename_list: List[str],
        file_group_size_collection: Dict[int, set],
    ):
        file_added_count = 0
        console.progress("Scanning directory [{0}]".format(base_dir))

        # fetch listing of files/dir in given base dir
        for filename_item in filename_list:
            # build full path to file and get filesize
            filename_full_path = "/".join([base_dir, filename_item])
            file_item_size = os.path.getsize(filename_full_path)

            # is file larger than minimum file size and meet include glob criteria?
            if (file_item_size >= minimum_filesize) and is_file_glob_match(
                filename_item
            ):
                console.progress(
                    "Found [{0}] [{1}]".format(filename_full_path, file_item_size)
                )

                # new file size index encountered?
                if file_item_size not in file_group_size_collection:
                    file_group_size_collection[file_item_size] = set()

                # add file item to grouped size set
                file_group_size_collection[file_item_size].add(filename_full_path)
                file_added_count += 1

        # return count of files added in this pass
        return file_added_count

    # process each scan dir given in list
    total_file_count = 0
    file_group_size_collection: Dict[int, set] = {}

    for scan_dir in scan_dir_list:
        # open scan_dir, process filename_list
        for base_dir, _, filename_list in os.walk(scan_dir):
            total_file_count += process_file_list(
                base_dir, filename_list, file_group_size_collection
            )

    # return total file count and files grouped by size
    return total_file_count, file_group_size_collection


def calc_file_group_size_checksum(
    console: Console, file_group_size_collection: Dict[int, set]
):
    def get_checksum(file_path: str):
        #  MD5 algo for a quick(ish) checksum
        hasher = hashlib.md5()
        with open(file_path, "rb") as fp:
            chunk = fp.read(FILE_CHUNK_MD5_SIZE)
            while chunk:
                hasher.update(chunk)
                chunk = fp.read(FILE_CHUNK_MD5_SIZE)

        return hasher.hexdigest()

    def calc_checksum_file_list(file_list: Set[str]):
        # calc checksums for each file in given list, grouped by identical checksums
        checksum_collection: Dict[str, list] = {}
        for file_item in file_list:
            file_checksum = get_checksum(file_item)
            console.progress("Checksum: [{0}] [{1}]".format(file_item, file_checksum))

            # new file checksum index encountered?
            if file_checksum not in checksum_collection:
                checksum_collection[file_checksum] = []

            # add file checksum to grouped collection list
            checksum_collection[file_checksum].append(file_item)

        # return collection of duplicate files grouped by their checksum
        return {
            file_checksum: file_list
            for file_checksum, file_list in checksum_collection.items()
            if (len(file_list) > 1)
        }

    # discover file group size collections broken down into checksum sub-groupings
    return {
        file_item_size: calc_checksum_file_list(file_list)
        for file_item_size, file_list in file_group_size_collection.items()
        if (len(file_list) > 1)
    }


def generate_report(
    console: Console,
    file_group_checksum_collection: Dict[int, Dict[str, list]],
    report_file_path: str,
    report_format_json: bool,
):
    report_file_handle = None
    duplicate_file_count = 0

    def write_report_line(report_line: str = "", line_feed: bool = True):
        # write line either to console, or file
        if report_file_path is None:
            console.write(report_line)

        else:
            report_file_handle.write(report_line + ("\n" if line_feed else ""))

    # iterate over file item size collection
    for (
        file_item_size,
        file_checksum_collection,
    ) in file_group_checksum_collection.items():
        # iterate over file checksum collection
        for file_checksum, file_list in file_checksum_collection.items():
            if duplicate_file_count:
                if report_format_json:
                    # next file duplicate JSON object item
                    write_report_line(",")

                else:
                    # add line break between previous duplicate file grouping
                    write_report_line()

            else:
                # start of report - open file, or write header to console
                if report_file_path is not None:
                    try:
                        report_file_handle = open(report_file_path, "w")

                    except IOError:
                        console.exit_error(
                            "Unable to write report to [{0}]".format(report_file_path)
                        )

                    if report_format_json:
                        # open JSON array
                        write_report_line("[")

                else:
                    console.write("Duplicate files found:\n")

            duplicate_file_count += 1
            if report_format_json:
                # writing to report file in JSON format
                write_report_line(
                    json.dumps(
                        {
                            "md5": file_checksum,
                            "size": file_item_size,
                            "fileList": file_list,
                        },
                        separators=REPORT_FILE_FORMAT_JSON_SEPARATORS,
                    ),
                    False,
                )

            else:
                # write duplicate file group header
                write_report_line(
                    "{0} @ {1} bytes".format(file_checksum, file_item_size)
                )

                for file_item in file_list:
                    # output identical file size/checksum items
                    write_report_line("\t{0}".format(file_item))

    if report_file_path is not None:
        # if report to file close handle
        if report_file_handle is not None:
            if report_format_json:
                # close JSON array
                write_report_line("\n]")

            # close file and output file written
            report_file_handle.close()
            console.write("Report written to: {0}\n".format(report_file_path))

    else:
        # add final line break after report output
        console.write()

    # return total number of duplicate files found
    return duplicate_file_count


def main():
    console = Console()

    # read CLI arguments
    (
        scan_dir_list,
        file_include_regexp_list,
        minimum_filesize,
        Console.progress_enabled,
        report_file_path,
        report_as_json,
    ) = read_arguments(console)

    # scan source directories for files to compare, grouped by filesize
    total_file_count, file_group_size_collection = scan_dir_list_recursive(
        console, scan_dir_list, file_include_regexp_list, minimum_filesize
    )

    # any files found? exit if none
    if not total_file_count:
        console.exit_error("Unable to locate files for comparing")

    # checksum all filesize grouped lists
    file_group_checksum_collection = calc_file_group_size_checksum(
        console, file_group_size_collection
    )

    # generate duplicate report to screen or file
    duplicate_file_count = generate_report(
        console,
        file_group_checksum_collection,
        report_file_path,
        report_as_json,
    )

    # write final duplicate counts
    console.write("Files considered: {0}".format(total_file_count))

    console.write(
        "Total duplicates: {0}".format(duplicate_file_count)
        if (duplicate_file_count)
        else "No duplicates found"
    )

    # finished successfully
    sys.exit(0)


if __name__ == "__main__":
    main()
