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

 Python program to (de)obfuscate and rehash Uplink REDSHRT data files, does not
 yet support the automatic decompression of REDSHRT archive files
 (zip compression).

 File validity, buffer block size, and program safeguards are based on how
 Uplink handles said mechanisms, and are far from infallible. If you try to
 break them you will probably be successful, so handle with care!
'''
'''
 A note to the devs of Uplink:
 
 To begin, I only bother to do this kind of thing for games that I love.
 Uplink is one of my favorite games of all time, and I knew that eventually I
 would start to peer under the hood. Plus, given the genre, I think that it's
 more than appropriate.
 
 This project was interesting to me, it's rare for a savefile scheme to have any
 protection mechanisms that provide some challenge. The mechanisms specifically
 were simple, but well chosen to delay access / modification, and match the
 spirit of the game beautifully.
 
 I actually didn't know about the Book2 crypto puzzle until well after I
 finished the core code, unfortunately it seems I was very late to the party.
 Regardless, it was fun solving the REDSHRT bit without any spoilers or prebuilt
 tools, and I'm glad to now know the purpose of the data in world.dat.
 
 Thanks :)
'''
'''
 Finnaly: if anybody knows where I can buy an original game DVD, source DVD, and
          or the game bible materials disc, please let me know.
'''

import os
import sys
import argparse
import hashlib

# Make sure the right version of python is being used.
try:
    assert sys.version_info >= (3, 0, 0), "python version error"
except AssertionError:
    print("Error: python3 is required to run this program!", file=sys.stderr)
    exit(1)

# Two verisons of REDSHRT and v2 hash modified sha1 checksum.
MAGIC_NUMS = [b'REDSHIRT\x00', b'REDSHRT2\x00']
# Known inner file headers used inside REDSHRT files (zip, mp3, savefile).
DATA_MAGIC_NUMS = [b'PK\x03\x04', b'\xFF\xFB', b'SAV']

# REDSHRT file magic is 8 bytes plush null byte.
MAGIC_SIZE = 9
# REDSHRT file uses modified sha1 hash.
HASH_SIZE = 20
# Uplink uses 16kiB buffer for checksum and (de)obfuscation operations.
BUFF_SIZE = 16384

# Entry point fuction, handles ui and file io.
def main(operation, input_path, output_path, verbosity, safety_off):
    # Make sure input file exists and is not empty.
    if not os.path.isfile(input_path):
        print("[!] Error:", input_path, "not found!", file=sys.stderr)
        exit(1)

    # Check if output file path is a directory, and if so use input file name.
    if os.path.basename(output_path) == "":
        output_path += os.path.basename(input_path)
    
    # Make sure input and output location are not the same.
    if input_path == output_path:
        print("[!] Error: cannot modify file in-place!", file=sys.stderr)
        exit(1)
    
    # Open input file for header check.
    input_file = open(input_path, "rb")
    
    # Check header to make sure we have a valid input file.
    if verbosity:
        print("[+] Checking", input_path, "for REDSHRT header.")
    
    header_ver, orig_hash = check_header(input_file)
    
    if not header_ver:
        print("[!] Error:", input_path, "is not a REDSHRT file!",
              file=sys.stderr)
        input_file.close()
        exit(1)
    
    # Print the current hash if verbose output was requested.
    if header_ver == 2 and verbosity:
        print("[#] Header hash:", orig_hash.hex())
    
    # Recalculated file hash for comparison / modification.
    new_hash = b'\x00' * 20
    
    # If version 2 we need to check validity of file by comparing hashes.
    if header_ver == 2:
        if operation == "decode":
            # Check for already decoded file.
            if orig_hash == (b'\x00' * 20):
                print("[#] Hash is zeroed: file might already be decoded!",
                    file=sys.stderr)
            
            # Generate new hash.
            new_hash = gen_hash(input_file)
            
            # If hashes don't match it is not considered a valid REDSHRT file.
            if orig_hash != new_hash:
                # Just warn if user used --force.
                if safety_off:
                    print("[#] Warning:", input_path, "has an incorrect hash!",
                          file=sys.stderr)
                    print("[#] File data may be corrupt or invalid!",
                          file=sys.stderr)
                # Unrecoverable error otherwise.
                else:
                    print("[!] Error:", input_path, "has an incorrect hash!",
                          file=sys.stderr)
                    print("[!] File data may be corrupt or invalid!",
                          file=sys.stderr)
                    exit(1)
            
            # Ensure correct read location for decode operation.
            input_file.seek((MAGIC_SIZE + HASH_SIZE), 0)
        else:
            # If hashe isn't zeroed assume that the file is already encoded.
            if orig_hash != b'\x00' * 20:
                if safety_off:
                    print("[#] Warning:", input_path, "has a non empty hash!",
                          file=sys.stderr)
                    print("[#] File may not be decoded!", file=sys.stderr)
                # Unrecoverable error otherwise.
                else:
                    print("[!] Error:", input_path, "has a non empty hash!",
                          file=sys.stderr)
                    print("[!] File may not be decoded!", file=sys.stderr)
                    exit(1)
            
            if operation == "encode":
                # Ensure correct read location for encode operation.
                input_file.seek((MAGIC_SIZE + HASH_SIZE), 0)
    
    # Check inner data for known headers and warn if it doesn't match.
    if operation == "strip":
        if not check_data(input_file, header_ver):
            if safety_off:
                print("[#] Warning:", input_path,
                    "data does not match a known signature!", file=sys.stderr)
                print("[#] File may not be decoded!", file=sys.stderr)
            else:
                print("[!] Error:", input_path,
                    "data does not match a known signature!", file=sys.stderr)
                print("[!] File may not be decoded!", file=sys.stderr)
                exit(1)
    
    # Create / override output file for writing modified data.
    output_file = open(output_path, "wb+")
    
    # Inform user of operation.
    if operation == "encode":
        print("[+] Writing encoded data to:", output_path)
    elif operation == "decode":
        print("[+] Writing decoded data to:", output_path)
    else:
        print("[+] Writing stripped data to:", output_path)
    
    if operation != "strip":
        # Run obfuscate / deobfuscate function.
        encode_decode(input_file, output_file, header_ver)
    else:
        strip_header(input_file, output_file, header_ver)
    
    # Don't need access to input data beyond this point.
    input_file.close()
    
    # If an encode operation was requested, we need to rehash the file.
    if operation == "encode" and header_ver == 2:
        print("[+] Rehashing data in:", output_path)
        # Ensure correct read location for hash operation.
        output_file.seek(MAGIC_SIZE + HASH_SIZE, 0)
        
        # Run rehash operation on obfuscated data.
        new_hash = gen_hash(output_file)
        
        # Write new hash to file.
        output_file.seek(MAGIC_SIZE, 0)
        output_file.write(new_hash)

        # Print the new hash if verbose output was requested.
        if verbosity:
            print("[#] New REDSHRT hash:", new_hash.hex())
    
    # Don't need access to output data beyond this point.
    output_file.close()
    
    # Inform user of completion.
    print("[+] done.")

# Make sure we are dealing with a REDSHRT file.
def check_header(input_file):
    # File header is at the start of the file.
    input_file.seek(0, 0)
    
    # Set empty header version (serves as an error code).
    header_ver = None
    # Original file hash before modification of data.
    file_hash = b'\x00' * 20
    
    # Read in file magic number (first 9 bytes).
    magic = input_file.read(MAGIC_SIZE)
    
    # Make sure file actually had MAGIC_SIZE bytes.
    if len(magic) != MAGIC_SIZE:
        return (header_ver, file_hash)
    
    # Check magic nuber against known good values.
    if magic == MAGIC_NUMS[0]:
        header_ver = 1
    elif magic == MAGIC_NUMS[1]:
        header_ver = 2
        # Version 2 files have a modified sha1 hash.
        file_hash = input_file.read(HASH_SIZE)
        
        if len(file_hash) != HASH_SIZE:
            header_ver = None
    
    return (header_ver, file_hash)

# Check inner data in (assumed decoded) REDSHRT file for known signatures.
def check_data(input_file, header_ver):
    # Set seek size for use in loop.
    if header_ver == 1:
        seek_size = MAGIC_SIZE
    else:
        seek_size = (MAGIC_SIZE + HASH_SIZE)
    
    for magic_num in DATA_MAGIC_NUMS:
        # Need to read data past the end of the header.
        input_file.seek(seek_size, 0)   
        
        # Get data magic / header.
        data_magic = input_file.read(len(magic_num))
        
        # Make sure byte count matches.
        if len(data_magic) != len(magic_num):
            return False
        
        # Check if we have a match.
        if data_magic == magic_num:
            return True
    
    # Value not in known signature list.
    return False

# Removes REDSHRT header info for use of data in files (zip, mp3).
def strip_header(input_file, output_file, header_ver):
    # Need to write data past the end of the header only.
    if header_ver == 1:
        input_file.seek(MAGIC_SIZE, 0)
    else:
        input_file.seek((MAGIC_SIZE + HASH_SIZE), 0)
    
    # Need to start writing data at the beginning of the file.
    output_file.seek(0, 0)
    
    # Copy first chunk of stripped bytes from file into bufffer.
    buff = input_file.read(BUFF_SIZE)
    
    # Write all stripped data from input file to output file.
    while buff:
        output_file.write(buff)
        buff = input_file.read(BUFF_SIZE)

# Generate checksum for REDSHRT data (assumes file position is intentional).
def gen_hash(file):
    # Create hash context object.
    sha1_ctxt = hashlib.sha1()
    
    # Load first chunk from file.
    buff = file.read(BUFF_SIZE)
    
    # Hash chunks.
    while buff:
        sha1_ctxt.update(buff)
        buff = file.read(BUFF_SIZE)
    
    # Create temporary hash to hold correct value while we do reordering.
    tmp_hash = bytearray(sha1_ctxt.digest())
    mod_hash = bytearray(b'\x00' * 20)
    
    '''
     Software implementations of SHA1 on LittleEndian systems reorder the
     final bytes of the hash to match the BigEndian used in the SHA1 spec.
     The Uplink devs removed the reordering loop from their implementation, I
     assume to throw people off the trail. :P
     To match this behavior, we run my slick version of the reordering loop,
     reversing the algo's reordering. :)
    '''
    for i in range(20):
        mod_hash[i] = tmp_hash[(((i // 4) * 4) + (3 - (i % 4)))]
    
    # Save modified hash value.
    new_hash = bytes(mod_hash)
    
    return new_hash

# (De)obfuscate REDSHRT file data (assumes file position is intentional).
def encode_decode(input_file, output_file, header_ver):
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
    
    '''
     The main body of the REDSHRT files is obfuscated by adding 128
     (10000000) to each byte, and deobfuscated by subtracting 128 from each
     byte. This really just flips the 8th bit in each byte (relying on how
     most systems handle overflow and underflow events). However, this can be
     more simply achieved with xoring, making the operation the same for
     obfuscation and deobfuscation.
    '''
    while buff:
        for i in range(len(buff)):
            buff[i] ^= 128
        
        # Write (de)obfuscated input chunk to output.
        output_file.write(bytes(buff))
        # Load next chunk.
        buff = bytearray(input_file.read(BUFF_SIZE))

# Entry point guard.
if __name__ == "__main__":
    # Setup parser for command line arguments.
    parser = argparse.ArgumentParser(
        prog="uprdec.py",
        description="Tool to (de)obfuscate Uplink REDSHRT files.")
    
    # Add arguments to parser.
    parser.add_argument("mode",
                        help="mode of operation: < encode || decode || strip >")
    parser.add_argument("input", help="path to input file")
    parser.add_argument("output", help="path to output file")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="use verbose output")
    parser.add_argument("-f", "--force", action="store_true",
                        help="ignore checksum when checking for file validity")
    
    # Fetch arguments from sys.argv[].
    args = parser.parse_args()
    
    # Check for valid mode of operation.
    if not args.mode in {"encode", "decode", "strip"}:
        parser.print_help(sys.stderr)
        exit(1)
    
    # Start program with user arguments.
    main(operation = args.mode, input_path = args.input,
         output_path = args.output,
         verbosity = True if args.verbose else False,
         safety_off = True if args.force else False)
