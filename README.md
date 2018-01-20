# safefs 
MacOS FUSE Filesystem using a simple polyalphabetic substitution cipher for file encryption
Copyright (C) 2018 David Johnston
All rights reserved

This is a MacOS FUSE filesystem that uses an 8 digit pin code to encrypt files using a simple polyalphabetic substitution cipher.
You can use this to encrypt your cloud files by placing the storage folder in a cloud sync folder location.
Make sure that you place the access folder outside of any cloud sync folder locations otherwise the plain text versions of the files will also be synchronised with the cloud.

## Features

The file encryption strategy used has the following features:

	1. A polyalphabetic substitution cipher is used to encipher and decipher file content
	2. A separate randomly generated cipher table is used for each file so that two files with the same plain text result in different cipher text
	3. An 8 character pin code is used to derive the cipher key that is used with the cipher table to encipher and decipher the text
	4. 1TB of plain text in a single file is required before the encipherment sequence is repeated
	5. An MD5 hash of the pin code is stored in a file .safefs to check that the correct key is being used to unlock the filesystem
	6. A different MD5 hash of the pin code is used to encode each cipher table; the cipher table is stored with the file

## Caveats

	1. Don't use this to protect state secrets. The algorithm has not been verified to determine its strength to resist attacks on the generated cipher text
	2. The algorithm can encipher about 100MB per second and decipher about 240MB per second on a 2015 MacBook Pro laptop

## Files

| File          | Purpose                                  |
| ------------  | ---------------------------------------- |
| cipher-test.c | Unit tests for the cipher algorithm      |
| cipher.c      | The polyalphabetic cipher algorithm      |
| cipher.h      | Header file for cipher algorithm         |
| global.h      | Reference MD5 implementation header file |
| logging.c     | Logging methods                          |
| logging.h     | Logging methods header file              |
| makefile      | Make file                                |
| md5.c         | Reference MD5 implementation             |
| md5.h         | Reference MD5 implementation header file |
| node.c        | Linked list implementation               |
| node.h        | Linked list header file                  |
| safefs-test.c | FUSE filesystem tests                    |
| safefs.c      | FUSE filesystem implementation           |
| state.h       | FUSE state definition header file        |

## How to compile binary

	make all

## Example to mount a filesystem with safefs

	1. mkdir -p test-store.noindex
	2. mkdir -p test-access
	3. ulimit -c 0
	4. safefs -ovolname=safefs-test test-store.noindex/ test-access/

	Files are accessed via the test-access folder and the encrypted versions are stored in the test-store.noindex folder.

## Example to unmount a filesystem

	1. umount test-access

## Copyrights

	1. This software is Copyright (C) 2018, David Johnston. All rights reserved.
	2. The MD5 implementation is Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All rights reserved.

## Notices

	1. This software uses the RSA reference implementation of MD5 in an unmodified form as a library. Copyrights and licenses are retained in the source files.

