#!/usr/bin/env python

import argparse
import fnmatch
import hashlib
import os
import os.path as path
import re
import sys

FILE_CHUNK_MD5_SIZE = 4096
last_progress_line_length = 0


def exit_error(message):
	sys.stderr.write('Error: {0}\n'.format(message))
	sys.exit(1)

def write_progress_message(enabled,message = ''):
	global last_progress_line_length

	# writing out progress?
	if (not enabled):
		return

	if (last_progress_line_length > 0):
		# back to beginning of current line
		sys.stdout.write('\r')

	# write out progress line
	sys.stdout.write(message)

	# if new message is shorter than previous - erase additional characters with spaces
	if (last_progress_line_length > len(message)):
		erase_char_count = last_progress_line_length - len(message)
		sys.stdout.write(
			(' ' * erase_char_count) +
			('\b' * erase_char_count)
		)

	# remember current progress message length
	last_progress_line_length = len(message)

def read_arguments():
	# create argument parser
	parser = argparse.ArgumentParser(description = 'Recursively scan one or more directories for duplicate files.')

	parser.add_argument('scandir',help = 'list of directories to scan for duplicates',nargs = '+')
	parser.add_argument('--include',help = 'glob filespec(s) to include in file scan, if omitted all files considered',nargs = '*')
	parser.add_argument('--min-size',help = 'minimum file size to be considered',type = int)
	parser.add_argument('--progress',action = 'store_true',help = 'show progress during file diffing')
	parser.add_argument('--report-file',help = 'output duplicate report to file, rather than screen')

	args_list = parser.parse_args()

	# strip trailing slashes from each given scandir
	scan_dir_list = map(
		lambda dir: re.sub(r'^(.+?)/+$',r'\1',dir),
		args_list.scandir
	)

	# ensure all scan dirs exist
	for scan_dir in scan_dir_list:
		if (not path.isdir(scan_dir)):
			exit_error('Invalid directory {0}'.format(scan_dir))

	# ensure each given scan directory do not overlap in the filesystem
	for source in range(len(scan_dir_list)):
		for dest in range(source + 1,len(scan_dir_list)):
			if (
				(scan_dir_list[source].find(scan_dir_list[dest]) == 0) or
				(scan_dir_list[dest].find(scan_dir_list[source]) == 0)
			):
				exit_error('Scan directory {0} overlaps with {1}'.format(scan_dir_list[source],scan_dir_list[dest]))

	# ensure all --include file globs are valid and compile to regular expressions for use
	file_include_regexp_list = set()
	if (args_list.include):
		for file_include_glob in args_list.include:
			if (not re.search(r'^[A-Za-z0-9-.*?!\[\]]+$',file_include_glob)):
				# invalid glob
				exit_error('Invalid file include glob {0}'.format(file_include_glob))
			else:
				# valid - add to list as a regular expression compiled from fnmatch
				file_include_regexp_list.add(
					re.compile(fnmatch.translate(file_include_glob))
				)

	# determine minimum file size to consider
	minimum_filesize = 0 if (args_list.min_size is None) else args_list.min_size

	# return arguments
	return (
		scan_dir_list,
		file_include_regexp_list,
		minimum_filesize,
		args_list.progress,args_list.report_file
	)

def scan_dir_list_recursive(scan_dir_list,file_include_regexp_list,minimum_filesize,progress_display):
	# setup file match glob function
	if (len(file_include_regexp_list) < 1):
		def is_file_glob_match(filename):
			# always a match if no globs defined
			return True

	else:
		def is_file_glob_match(filename):
			# at least one file_include_regexp_list item must match the filename
			return any(regexp.match(filename) for regexp in file_include_regexp_list)

	# setup directory processor - called recursively for each sub-dir
	def process_dir_files(base_dir,file_group_size_collection):
		file_added_count = 0
		sub_dir_list = set()

		write_progress_message(progress_display,'Scanning directory: {0}'.format(base_dir))

		# fetch listing of files/dir in given base dir
		for dir_item in os.listdir(base_dir):
			# add full path to file/dir item
			dir_item_full_path = '{0}/{1}'.format(base_dir,dir_item)

			# is item a file?
			if (path.isfile(dir_item_full_path)):
				# yes - grab file size
				file_item_size = path.getsize(dir_item_full_path)

				# is file larger than minimum file size and meet include glob criteria?
				if (
					(file_item_size >= minimum_filesize) and
					is_file_glob_match(dir_item)
				):
					write_progress_message(progress_display,'Found: {0} [{1}]'.format(dir_item_full_path,file_item_size))

					# new file size index encountered?
					if (file_item_size not in file_group_size_collection):
						file_group_size_collection[file_item_size] = set()

					# add file item to grouped size set
					file_group_size_collection[file_item_size].add(dir_item_full_path)
					file_added_count += 1

			else:
				# is a directory - process after all files
				sub_dir_list.add(dir_item_full_path)

		# now recursively process any found sub directories
		for sub_dir_item in sub_dir_list:
			file_added_count += process_dir_files(sub_dir_item,file_group_size_collection)

		# return total count of files added in this pass
		return file_added_count

	# process each scan dir given in list
	total_file_count = 0
	file_group_size_collection = {}

	for scan_dir in scan_dir_list:
		total_file_count += process_dir_files(scan_dir,file_group_size_collection)

	# flush last progress message
	write_progress_message(progress_display)

	# return scanned files grouped by size and total files
	return total_file_count,file_group_size_collection

def file_group_size_checksum(file_group_size_collection,progress_display):

	def calc_file_checksum(file_path):
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
			file_checksum = calc_file_checksum(file_item)

			write_progress_message(
				progress_display,
				'Calc checksum: {0} [{1}]'.format(file_item,file_checksum)
			)

			# new file checksum index encountered?
			if (file_checksum not in checksum_collection):
				checksum_collection[file_checksum] = set()

			# add file checksum to grouped collection
			checksum_collection[file_checksum].add(file_item)

		# return collection of duplicate files grouped by their checksum
		return {
			file_checksum: file_list
			for (file_checksum,file_list) in checksum_collection.iteritems() if (len(file_list) > 1)
		}

	# discover file group size collections broken down into checksum sub-groupings
	file_checksums_grouped = {
		file_item_size: calc_checksum_file_list(file_list)
		for (file_item_size,file_list) in file_group_size_collection.iteritems() if (len(file_list) > 1)
	}

	# flush last progress message
	write_progress_message(progress_display)

	return file_checksums_grouped

def generate_report(file_group_checksum_collection,duplicate_report_file):
	report_file_handle = None
	duplicate_file_count = 0

	def write_report_line(report_line = ''):
		if (duplicate_report_file is None):
			print(report_line)

		else:
			report_file_handle.write(report_line + '\n')

	# iterate over file item size collection
	for (file_item_size,file_checksum_collection) in file_group_checksum_collection.iteritems():
		# iterate over file checksum collection
		for (file_checksum,file_list) in file_checksum_collection.iteritems():
			if (duplicate_file_count > 0):
				# add line break between previous dupe file grouping
				write_report_line()

			else:
				# open report file, or write report header to console
				if (duplicate_report_file is not None):
					try:
						report_file_handle = open(duplicate_report_file,'w')
					except IOError:
						exit_error('Unable to write duplicate report to {0}'.format(duplicate_report_file))

				else:
					print('Duplicate files found:\n')

			# write duplicate file group header
			write_report_line('MD5: {0}, Size: {1} bytes'.format(file_checksum,file_item_size))

			for dupe_file_item in file_list:
				# output identical file size/checksum items
				write_report_line('\t{0}'.format(dupe_file_item))
				duplicate_file_count += 1

	if (duplicate_report_file is not None):
		# if output to file close handle
		if (report_file_handle is not None):
			report_file_handle.close()

	else:
		# add additional console line break after report output
		print

	# return total number of duplicate files found
	return duplicate_file_count

def main():
	# read CLI arguments
	scan_dir_list,file_include_regexp_list,minimum_filesize,progress_display,duplicate_report_file = read_arguments()

	# scan source directories for files to compare
	total_file_count,file_group_size_collection = scan_dir_list_recursive(
		scan_dir_list,file_include_regexp_list,
		minimum_filesize,progress_display
	)

	# any files found? exit now if none
	if (total_file_count < 1):
		exit_error('Unable to locate any files for comparing')

	print('Total files found for comparing: {0}'.format(total_file_count))

	# checksum all files grouped into file sizes
	file_group_checksum_collection = file_group_size_checksum(file_group_size_collection,progress_display)

	# generate duplicate report to screen or file
	duplicate_file_count = generate_report(file_group_checksum_collection,duplicate_report_file)

	# write out final duplicate file count
	print(
		'Total file duplicates: {0}'.format(duplicate_file_count) if (duplicate_file_count > 0)
		else 'No duplicates found'
	)

	# finished successfully
	sys.exit(0)


if (__name__ == '__main__'):
	main()
