#!/usr/bin/env python3
'''
 MIT License

 Copyright (c) 2019 anicca048

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
'''
'''
 uprdec.py, Uplink REDSHRT decoder

 Python program to (de)obfuscate Uplink REDSHRT data files, does not support
 decompression of REDSHRT archive files (yet!).

 File validity and program safeguards are based on how Uplink handles said
 checks, and are far from infaliable. If you try to break them you will 
 probably be successful, so handle with care!
'''

import os
import sys
import argparse
import hashlib

# Make sure the right version of python is being used.
try:
    assert sys.version_info >= (3, 0, 0), "python version error"
except AssertionError:
    print("error: python3 is required to run this program!")
    exit(1)

# Two verisons of REDSHRT and v2 hash modified sha1 checksum.
MAGIC_NUMS = [b'REDSHIRT\x00', b'REDSHRT2\x00']
# REDSHRT file magic is 8 bytes plush null byte.
MAGIC_SIZE = 9
# REDSHRT file uses modified sha1 hash.
HASH_SIZE = 20
# Uplink uses 16kiB buffer for checksum and (de)obfuscation operations.
BUFF_SIZE = 16384

# Track header version across program.
header_ver = 0
# Original file hash before modification of data.
orig_hash = b'\x00' * 20
# Recalculated file hash for comparison / modification.
new_hash = b'\x00' * 20

# Make sure we are dealing with a REDSHRT file.
def check_header(input_file):
	global header_ver, orig_hash
	
	# Read in file magic number (first 9 bytes).
	magic = input_file.read(MAGIC_SIZE)
	
	if len(magic) != MAGIC_SIZE:
		return -1
	
	# Check magic nuber against known good values.
	if magic == MAGIC_NUMS[0]:
		header_ver = 1
	elif magic == MAGIC_NUMS[1]:
		header_ver = 2
		# Version 2 files have a modified sha1 hash.
		orig_hash = input_file.read(HASH_SIZE)
		
		if len(orig_hash) != HASH_SIZE:
			return -1
	else:
		return -1

# Generate checksum for REDSHRT data.
def rehash(output_file):
	global orig_hash, new_hash
	
	# Create hash context object.
	sha1_ctxt = hashlib.sha1()
	
	# Load first chunk from file.
	buff = output_file.read(BUFF_SIZE)
	
	# Hash chunks.
	while buff:
		sha1_ctxt.update(buff)
		buff = output_file.read(BUFF_SIZE)
	
	# Create temporary hash to hold correct value while we do reordering.
	tmp_hash = bytearray(sha1_ctxt.digest())
	mod_hash = bytearray(b'\x00' * 20)
	
	# Must reorder correct hash to replicate modified sha1 used by Uplink.
	for i in range(20):
		mod_hash[i] = tmp_hash[(((i // 4) * 4) + (3 - (i % 4)))]
	
	# Save modified hash value.
	new_hash = bytes(mod_hash)

# (De)obfuscate REDSHRT file data.
def encode_decode(input_file, output_file):
	global header_ver
	
	# Write header to file.
	if header_ver == 1:
		output_file.write(MAGIC_NUMS[0])
	else:
		output_file.write(MAGIC_NUMS[1])
	
	# Write empty hash section for version 2 files.
	if header_ver == 2:
		output_file.write(b'\x00' * 20)
	
	# Load first data chunk.
	buff = bytearray(input_file.read(BUFF_SIZE))
	
	# (De)obfuscate data chunks.
	while buff:
		for i in range(len(buff)):
			buff[i] ^= 128
		
		# Write (de)obfuscated input chunk to output.
		output_file.write(bytes(buff))
		# Load next chunk.
		buff = bytearray(input_file.read(BUFF_SIZE))

# Entry point fuction, handles ui and file io.
def main(operation, input_path, output_path, verbosity, safety_off):
	# Make sure input file exists and is not empty.
	if not os.path.isfile(input_path):
		print("[!] Error:", input_path, "not found!")
		exit(1)

	# Check if output file path is a directory, and if so use input file name.
	if os.path.basename(output_path) == "":
		output_path += os.path.basename(input_path)
	
	# Make sure input and output location are not the same.
	if input_path == output_path:
		print("[!] Error: cannot modify file in-place!")
		exit(1)
	
	# Open input file for header check.
	input_file = open(input_path, "rb")
	
	# Check header to make sure we have a valid input file.
	if verbosity:
		print("[+] Checking", input_path, "for REDSHRT header.")
	
	if check_header(input_file) == -1:
		print("[!] Error:", input_path, "is not a REDSHRT file!")
		input_file.close()
		exit(1)
	
	# Print the current hash if verbose output was requested.
	if header_ver == 2 and verbosity:
		print("[#] Header hash:", orig_hash.hex())
	
	# If version 2 we need to check validity of file by comparing hashes.
	if header_ver == 2:
		if operation == "decode":
			rehash(input_file)
			
			# If hashes don't match it is not considered a valid REDSHRT file.
			if orig_hash != new_hash:
				# Just warn if user used --force.
				if safety_off:
					print("[#] Warning:", input_path, "has incorrect hash!")
					print("[#] File data may be corrupt or invalid!")
				# Unrecoverable error otherwise.
				else:
					print("[!] Error:", input_path, "has incorrect hash!")
					print("[!] File data may be corrupt or invalid!")
					exit(1)
			
			# Reset read location for decode operation.
			input_file.seek(MAGIC_SIZE + HASH_SIZE, 0)
		elif operation == "encode":
			# If hashes match assume that the file is already encoded.
			if orig_hash != b'\x00' * 20:
				if safety_off:
					print("[#] Warning:", input_path, " is already encoded!")
					print("[#] File must be decoded first!")
				# Unrecoverable error otherwise.
				else:
					print("[!] Error:", input_path, " is already encoded!")
					print("[!] File must be decoded first!")
					exit(1)
	
	# Create / override output file for writing modified data.
	output_file = open(output_path, "w+b")
	
	# Inform user of operation.
	if operation == "encode":
		print("[+] Writing encoded data to:", output_path)
	elif operation == "decode":
		print("[+] Writing decoded data to:", output_path)
	
	# Run obfuscate / deobfuscate function.
	encode_decode(input_file, output_file)
	
	# Cleanup.
	input_file.close()
	output_file.close()
	
	# If an encode operation was requested, we need to rehash the file.
	if operation == "encode" and header_ver == 2:
		print("[+] Rehashing data in:", output_path)
		# Reopen file in read-write mode for hashing.
		output_file = open(output_path, "r+b")
		# Seek past header to hash body.
		output_file.seek(MAGIC_SIZE + HASH_SIZE, 0)
		
		# Run rehash operation on obfuscated data.
		rehash(output_file)
		
		# Write new hash to file.
		output_file.seek(MAGIC_SIZE, 0)
		output_file.write(new_hash)
		
		# Final Cleanup.
		output_file.close()

		# Print the new hash if verbose output was requested.
		if verbosity:
			print("[#] New REDSHRT hash:", new_hash.hex())
	
	# Inform user of completion.
	print("[+] done.")

# Entry point guard.
if __name__ == "__main__":
	# Setup parser for command line arguments.
	parser = argparse.ArgumentParser(
		prog="uprdec.py",
		description="Tool to (de)obfuscate Uplink REDSHRT files.")
	
	# Add arguments to parser.
	parser.add_argument("mode", help="mode of operation: < encode || decode >")
	parser.add_argument("input", help="path to input file")
	parser.add_argument("output", help="path to output file")
	parser.add_argument("-v", "--verbose", action="store_true", 
						help="use verbose output")
	parser.add_argument("-f", "--force", action="store_true",
						help="ignore checksum when checking for file validity")
	
	# Fetch arguments from sys.argv[].
	args = parser.parse_args()
	
	# Check for valid mode of operation.
	if args.mode != "encode" and args.mode != "decode":
		parser.print_help(sys.stderr)
		exit(1)
	
	# Start program with user arguments.
	main(operation = args.mode, input_path = args.input,
		 output_path = args.output,
		 verbosity = True if args.verbose else False,
		 safety_off = True if args.force else False)

