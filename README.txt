Description:
----------------------
crypt.h and crypt.cpp are responsible for encrypting and decrypting.
nordic_backup.h and nordic_backup.cpp are where WndProc is and where the window gets created.
Resource.h is included because it defines the message ID for encrypt and decrypt buttons.

Input will be either a file or directory to encrypt.
Output will be the file to write encrypted data to or a directory to write encrypted files to.

If the output directory tree does not exist then the program should create it for you.
If input is a directory then output must also be a directory. If input is a file then output must also be a file.

Encryption method used is MSDN's CryptoAPI Next Generation.

Usage:
----------------------
Encrypting:
Instance 1:
Input: C:\file.txt
Output: C:\encrypted.txt

Will encrypt file.txt and write it out as encrypted.txt.

Instance 2:
Input: C:\dir\
Output: C:\encrypted\

Will encrypt all of dir\ and write the files in encrypted\ with the same file names.

Decrypting:
Instance 1:
Input: C:\encrypted.txt
Output: C:\decrypted.txt

Will decrypt encrypted.txt and write it out as decrypted.txt.

Instance 2:
Input: C:\encrypted\
Output: C:\decrypted\

Will decrypt all files in encrypted\ and write them to decrypted with the same file names.
----------------------
