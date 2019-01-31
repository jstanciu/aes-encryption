#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <memory>
#include <string>
#include <bcrypt.h>

bool encrypt_file(const std::wstring &plain_file, const std::wstring &cipher_file,
                  BYTE *key_data, DWORD key_data_size);

bool decrypt_file(const std::wstring &cipher_file, const std::wstring &plain_file,
                  BYTE *key_data, DWORD key_data_size);

bool encrypt_directory(const std::wstring &plain_directory, const std::wstring &cipher_directory,
                       BYTE *key_data, DWORD key_data_size);

bool decrypt_directory(const std::wstring &cipher_directory, const std::wstring &plain_directory,
                       BYTE *key_data, DWORD key_data_size);