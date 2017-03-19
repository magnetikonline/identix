#!/usr/bin/env python

import argparse
import fcntl
import fnmatch
import hashlib
import json
import os
import os.path
import re
import struct
import sys
import termios
import time

FILE_CHUNK_MD5_SIZE = 4096
REPORT_FILE_FORMAT_TEXT = 'text'
REPORT_FILE_FORMAT_JSON = 'JSON'
REPORT_FILE_FORMAT_JSON_SEPARATORS = (',',':')


class Console:
	TERMINAL_CONNECTED = sys.stdout.isatty()

	STDOUT_FILENO = sys.stdout.fileno()
	STRUCT_PACK_ZERO_ZERO = struct.pack('HH',0,0)
	TERMINAL_SIZE_CACHE_SECONDS = 2

	CURSOR_START_LINE_CLEAR_RIGHT = '{0}{1}'.format('\r','\x1b[K')

	class TERM_COLOR:
		RESET = '\033[39m'
		YELLOW = '\033[33m'

	progress_enabled = False

	_progress_active = False
	_terminal_size = None

	def _get_terminal_size(self):
		now_timestamp = int(time.time())

		if (
			(Console._terminal_size is None) or
			((Console._terminal_size[0] + Console.TERMINAL_SIZE_CACHE_SECONDS) <= now_timestamp)
		):
			# (re-)fetch current terminal dimensions
			data = fcntl.ioctl(
				Console.STDOUT_FILENO,
				termios.TIOCGWINSZ,
				Console.STRUCT_PACK_ZERO_ZERO
			)

			Console._terminal_size = (
				now_timestamp,
				struct.unpack('HH',data) # stored as rows X columns
			)

		return Console._terminal_size[1]

	def _get_text_truncated(self,full_text,max_length):
		full_text_length = len(full_text)
		if (full_text_length < max_length):
			# no need for truncation
			return full_text

		# determine dot gap length - 5% of max length, plus two space characters
		dot_gap = int(max_length * 0.05) + 2
		if (dot_gap < 3):
			dot_gap = 3

		# calculate split size - if too small just truncate and bail
		split_size = int((max_length - dot_gap) / 2)
		if (split_size < 5):
			return full_text[:max_length].strip()

		# return [FIRST_CHUNK ... LAST_CHUNK]
		return '{0} {1} {2}'.format(
			full_text[:split_size].strip(), +
			((max_length - (split_size * 2)) - 2) * '.',
			full_text[0 - split_size:].strip()
		)

	def _stdout_write_flush(self,text):
		sys.stdout.write(text)
		sys.stdout.flush()

	def _progress_finish(self):
		if (Console._progress_active):
			# clean up progress line from terminal, reset foreground color
			Console._progress_active = False
			self._stdout_write_flush(
				Console.CURSOR_START_LINE_CLEAR_RIGHT +
				Console.TERM_COLOR.RESET
			)

	def exit_error(self,message):
		self._progress_finish()
		sys.stderr.write('Error: {0}\n'.format(message))
		sys.exit(1)

	def write(self,text = ''):
		self._progress_finish()
		print(text)

	def progress(self,text):
		# only display progress if connected to a terminal
		if (
			(not Console.TERMINAL_CONNECTED) or
			(not Console.progress_enabled)
		):
			return

		# fetch terminal height and width
		_,max_text_width = self._get_terminal_size()
		write_list = []

		if (not Console._progress_active):
			# commence progress mode
			Console._progress_active = True
			write_list.append(Console.TERM_COLOR.YELLOW)

		# write progress message
		write_list.append(
			Console.CURSOR_START_LINE_CLEAR_RIGHT +
			self._get_text_truncated(text,max_text_width)
		)

		self._stdout_write_flush(''.join(write_list))

def read_arguments():
	console = Console()

	# create argument parser
	parser = argparse.ArgumentParser(description = 'Recursively scan one or more directories for duplicate files.')

	parser.add_argument(
		'scandir',
		help = 'source directory/directories for scanning',
		nargs = '+'
	)

	parser.add_argument(
		'--include',
		help = 'glob filespec(s) to include in scan, if omitted all files are considered',
		nargs = '*'
	)

	parser.add_argument(
		'--min-size',
		help = 'minimum filesize considered',
		type = int
	)

	parser.add_argument(
		'--progress',
		action = 'store_true',
		help = 'show progress during file diffing'
	)

	parser.add_argument(
		'--report-file',
		help = 'output duplicate report to file, rather than console'
	)

	parser.add_argument(
		'--report-file-format',
		choices = [REPORT_FILE_FORMAT_TEXT,REPORT_FILE_FORMAT_JSON],
		help = 'output format of duplicate report file'
	)

	arg_list = parser.parse_args()

	# ensure all scan dirs exist
	scan_dir_list = arg_list.scandir
	for scan_dir in scan_dir_list:
		if (not os.path.isdir(scan_dir)):
			console.exit_error('Invalid directory [{0}]'.format(scan_dir))

	# get canonical path of each scan dir
	scan_dir_list = map(
		lambda scandir: os.path.realpath(scandir),
		arg_list.scandir
	)

	# ensure each given scan directory does not overlap
	for source_index in range(len(scan_dir_list)):
		for dest_index in range(source_index + 1,len(scan_dir_list)):
			if (
				(scan_dir_list[source_index].find(scan_dir_list[dest_index]) == 0) or
				(scan_dir_list[dest_index].find(scan_dir_list[source_index]) == 0)
			):
				console.exit_error('Scan directory [{0}] overlaps with [{1}]'.format(
					scan_dir_list[source_index],
					scan_dir_list[dest_index]
				))

	# ensure all [--include] file globs are valid and compile to regular expressions via fnmatch
	file_include_regexp_list = set()
	if (arg_list.include):
		for file_include_glob in arg_list.include:
			if (not re.search(r'^[A-Za-z0-9_.*?!\-\[\]]+$',file_include_glob)):
				# invalid glob
				console.exit_error('Invalid file include glob [{0}]'.format(file_include_glob))

			# valid - add to list as a regular expression compiled from fnmatch
			file_include_regexp_list.add(
				re.compile(fnmatch.translate(file_include_glob))
			)

	# determine minimum file size to consider
	minimum_filesize = 0
	if (arg_list.min_size is not None):
		minimum_filesize = arg_list.min_size

	# the [--report-file-format] option can only be used when writing report to file
	if (
		(arg_list.report_file is None) and
		(arg_list.report_file_format is not None)
	):
		console.exit_error('Argument [--report-file-format] only valid with [--report-file]')

	# return arguments
	return (
		set(scan_dir_list),
		file_include_regexp_list,
		minimum_filesize,
		arg_list.progress,
		arg_list.report_file,
		(
			False
			if (arg_list.report_file_format is None)
			else (arg_list.report_file_format == REPORT_FILE_FORMAT_JSON)
		)
	)

def scan_dir_list_recursive(scan_dir_list,file_include_regexp_list,minimum_filesize):
	console = Console()

	# setup file match glob function
	if (file_include_regexp_list):
		def is_file_glob_match(filename):
			# at least one file_include_regexp_list item must match the filename
			# note: using .match() here, as what's expected to be used with fnmatch.translate()
			return any(
				regexp.match(filename)
				for regexp in file_include_regexp_list
			)

	else:
		def is_file_glob_match(filename):
			# always a match if no globs defined
			return True

	# setup directory processor - called recursively for each sub-dir
	def process_file_list(base_dir,filename_list,file_group_size_collection):
		file_added_count = 0
		console.progress('Scanning directory [{0}]'.format(base_dir))

		# fetch listing of files/dir in given base dir
		for filename_item in filename_list:
			# build full path to file and get filesize
			filename_full_path = '/'.join([base_dir,filename_item])
			file_item_size = os.path.getsize(filename_full_path)

			# is file larger than minimum file size and meet include glob criteria?
			if (
				(file_item_size >= minimum_filesize) and
				is_file_glob_match(filename_item)
			):
				console.progress('Found [{0}] [{1}]'.format(filename_full_path,file_item_size))

				# new file size index encountered?
				if (file_item_size not in file_group_size_collection):
					file_group_size_collection[file_item_size] = set()

				# add file item to grouped size set
				file_group_size_collection[file_item_size].add(filename_full_path)
				file_added_count += 1

		# return count of files added in this pass
		return file_added_count

	# process each scan dir given in list
	total_file_count = 0
	file_group_size_collection = {}

	for scan_dir in scan_dir_list:
		# open scan_dir, process filename_list
		for base_dir,dir_list,filename_list in os.walk(scan_dir):
			total_file_count += process_file_list(
				base_dir,
				filename_list,
				file_group_size_collection
			)

	# return total file count and files grouped by size
	return total_file_count,file_group_size_collection

def calc_file_group_size_checksum(file_group_size_collection):
	console = Console()

	def get_checksum(file_path):
		# using MD5 algorithm for quick checksum
		hasher = hashlib.md5()
		with open(file_path) as fp:
			for file_chunk in iter(lambda: fp.read(FILE_CHUNK_MD5_SIZE),''):
				hasher.update(file_chunk)

		return hasher.hexdigest()

	def calc_checksum_file_list(file_list):
		# calc checksums for each file in given list, grouped by identical checksums
		checksum_collection = {}
		for file_item in file_list:
			file_checksum = get_checksum(file_item)
			console.progress('Checksum: [{0}] [{1}]'.format(file_item,file_checksum))

			# new file checksum index encountered?
			if (file_checksum not in checksum_collection):
				checksum_collection[file_checksum] = []

			# add file checksum to grouped collection list
			checksum_collection[file_checksum].append(file_item)

		# return collection of duplicate files grouped by their checksum
		return {
			file_checksum: file_list
			for file_checksum,file_list in checksum_collection.iteritems() if (len(file_list) > 1)
		}

	# discover file group size collections broken down into checksum sub-groupings
	return {
		file_item_size: calc_checksum_file_list(file_list)
		for file_item_size,file_list in file_group_size_collection.iteritems() if (len(file_list) > 1)
	}

def generate_report(file_group_checksum_collection,report_file,report_format_json):
	console = Console()
	report_file_handle = None
	duplicate_file_count = 0

	def write_report_line(report_line = '',line_feed = True):
		# write line either to console, or file
		if (report_file is None):
			console.write(report_line)

		else:
			report_file_handle.write(report_line + ('\n' if line_feed else ''))

	# iterate over file item size collection
	for file_item_size,file_checksum_collection in file_group_checksum_collection.iteritems():
		# iterate over file checksum collection
		for file_checksum,file_list in file_checksum_collection.iteritems():
			if (duplicate_file_count):
				if (report_format_json):
					# next file duplicate JSON object item
					write_report_line(',')

				else:
					# add line break between previous duplicate file grouping
					write_report_line()

			else:
				# start of report - open file, or write header to console
				if (report_file is not None):
					try:
						report_file_handle = open(report_file,'w')

					except IOError:
						console.exit_error('Unable to write report to [{0}]'.format(report_file))

					if (report_format_json):
						# open JSON array
						write_report_line('[')

				else:
					console.write('Duplicate files found:\n')

			duplicate_file_count += 1
			if (report_format_json):
				# writing to report file in JSON format
				write_report_line(
					json.dumps(
						{
							'md5': file_checksum,
							'size': file_item_size,
							'fileList': file_list
						},
						separators = REPORT_FILE_FORMAT_JSON_SEPARATORS
					),
					False
				)

			else:
				# write duplicate file group header
				write_report_line('{0} @ {1} bytes'.format(file_checksum,file_item_size))

				for file_item in file_list:
					# output identical file size/checksum items
					write_report_line('\t{0}'.format(file_item))

	if (report_file is not None):
		# if output to file close handle
		if (report_file_handle is not None):
			if (report_format_json):
				# close JSON array
				write_report_line('\n]')

			report_file_handle.close()

	else:
		# add final line break after report output
		console.write()

	# return total number of duplicate files found
	return duplicate_file_count

def main():
	# read CLI arguments
	(
		scan_dir_list,
		file_include_regexp_list,
		minimum_filesize,
		Console.progress_enabled,
		duplicate_report_file,
		duplicate_report_as_json
	) = read_arguments()

	console = Console()

	# scan source directories for files to compare, grouped by filesize
	total_file_count,file_group_size_collection = scan_dir_list_recursive(
		scan_dir_list,
		file_include_regexp_list,
		minimum_filesize
	)

	# any files found? exit if none
	if (not total_file_count):
		console.exit_error('Unable to locate files for comparing')

	# checksum all filesize grouped lists
	file_group_checksum_collection = calc_file_group_size_checksum(file_group_size_collection)

	# generate duplicate report to screen or file
	duplicate_file_count = generate_report(
		file_group_checksum_collection,
		duplicate_report_file,
		duplicate_report_as_json
	)

	# write final duplicate counts
	console.write('Files considered: {0}'.format(total_file_count))

	console.write(
		'Total duplicates: {0}'.format(duplicate_file_count) if (duplicate_file_count)
		else 'No duplicates found'
	)

	# finished successfully
	sys.exit(0)


if (__name__ == '__main__'):
	main()
