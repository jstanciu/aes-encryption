#pragma once

#include "crypt.h"
#include <stdio.h>
#include <new>

using std::unique_ptr;
using std::wstring;

#pragma comment(lib, "bcrypt.lib")

#define CLOSE_HANDLE(handle) do { CloseHandle(handle); handle = INVALID_HANDLE_VALUE; } while(0);

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

static const BYTE rgbIV[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

bool get(DWORD &block_length,
	std::unique_ptr<BYTE[]> &iv_buffer, std::unique_ptr<BYTE[]> &key_object,
	BCRYPT_ALG_HANDLE *algorithm_handle, BCRYPT_KEY_HANDLE *key_handle,
	BYTE *key_bytes, DWORD key_bytes_size)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	DWORD bytes_written = 0;
	DWORD key_object_size = 0;

	status = BCryptOpenAlgorithmProvider(algorithm_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptOpenAlgorithmProvider() failed.", L"Error", MB_OK);
		return false;
	}

	status = BCryptGetProperty(*algorithm_handle, BCRYPT_BLOCK_LENGTH, reinterpret_cast<PUCHAR>(&block_length), sizeof(block_length), &bytes_written, 0);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptGetProperty() failed.", L"Error", MB_OK);
		return false;
	}

	if(block_length > sizeof(rgbIV))
	{
		MessageBox(nullptr, L"Block length is larger than our IV.", L"Error", MB_OK);
		return false;
	}

	iv_buffer.reset(new (std::nothrow) BYTE[block_length]);
	if(nullptr == iv_buffer.get())
	{
		MessageBox(nullptr, L"Failed to allocate iv buffer.", L"Error", MB_OK);
		return false;
	}

	memcpy(iv_buffer.get(), rgbIV, block_length);

	status = BCryptSetProperty(*algorithm_handle, BCRYPT_CHAINING_MODE,
		reinterpret_cast<PUCHAR>(const_cast<PWCHAR>(BCRYPT_CHAIN_MODE_CBC)), sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptSetProperty() failed.", L"Error", MB_OK);
		return false;
	}

	status = BCryptGetProperty(*algorithm_handle, BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&key_object_size), sizeof(key_object_size), &bytes_written, 0);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptGetProperty() failed.", L"Error", MB_OK);
		return false;
	}

	key_object.reset(new (std::nothrow) BYTE[key_object_size]);
	if(nullptr == key_object.get())
	{
		MessageBox(nullptr, L"Failed to allocate key_object.", L"Error", MB_OK);
		return false;
	}

	status = BCryptGenerateSymmetricKey(*algorithm_handle, key_handle,
		key_object.get(), key_object_size,
		reinterpret_cast<PUCHAR>((key_bytes)), key_bytes_size, 0);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptGenerateSymmetricKey() failed.", L"Error", MB_OK);
		return false;
	}

	return true;
}

bool encrypt_data(BYTE *plain_data, DWORD plain_data_size,
	std::unique_ptr<BYTE[]> &cipher_data, DWORD &cipher_data_size,
	BYTE *key_data, DWORD key_data_size)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_ALG_HANDLE algorithm_handle = INVALID_HANDLE_VALUE;
	BCRYPT_KEY_HANDLE key_handle = INVALID_HANDLE_VALUE;

	DWORD bytes_written = 0;
	DWORD block_length = 0;

	unique_ptr<BYTE[]> iv_buffer;
	unique_ptr<BYTE[]> key_object;

	if(false == get(block_length, iv_buffer, key_object, &algorithm_handle, &key_handle, key_data, key_data_size))
		return false;

	status = BCryptEncrypt(key_handle,
		plain_data, plain_data_size,
		nullptr, iv_buffer.get(), block_length,
		nullptr, 0, &cipher_data_size,
		BCRYPT_BLOCK_PADDING);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptEncrypt() failed.", L"Error", MB_OK);
		return false;
	}

	cipher_data.reset(new (std::nothrow) BYTE[cipher_data_size]);
	if(nullptr == cipher_data.get())
	{
		MessageBox(nullptr, L"Failed to allocate cipher data.", L"Error", MB_OK);
		return false;
	}

	status = BCryptEncrypt(key_handle,
		plain_data, plain_data_size,
		nullptr, iv_buffer.get(), block_length,
		cipher_data.get(), cipher_data_size, &bytes_written,
		BCRYPT_BLOCK_PADDING);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptEncrypt() failed.", L"Error", MB_OK);
		return false;
	}

	return true;
}

bool decrypt_data(BYTE *cipher_data, DWORD cipher_data_size,
	std::unique_ptr<BYTE[]> &plain_data, DWORD &plain_data_size,
	BYTE *key_data, DWORD key_data_size)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_ALG_HANDLE algorithm_handle = INVALID_HANDLE_VALUE;
	BCRYPT_KEY_HANDLE key_handle = INVALID_HANDLE_VALUE;

	DWORD bytes_written = 0;
	DWORD block_length = 0;

	unique_ptr<BYTE[]> iv_buffer;
	unique_ptr<BYTE[]> key_object;

	get(block_length, iv_buffer, key_object, &algorithm_handle, &key_handle, key_data, key_data_size);

	status = BCryptDecrypt(key_handle,
		cipher_data, cipher_data_size,
		nullptr, iv_buffer.get(), block_length,
		nullptr, 0, &plain_data_size,
		BCRYPT_BLOCK_PADDING);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptDecrypt() failed.", L"Error", MB_OK);
		return false;
	}

	plain_data.reset(new (std::nothrow) BYTE[plain_data_size]);
	if(nullptr == plain_data.get())
	{
		MessageBox(nullptr, L"Failed to allocate plain data.", L"Error", MB_OK);
		return false;
	}

	status = BCryptDecrypt(key_handle,
		cipher_data, cipher_data_size,
		nullptr, iv_buffer.get(), block_length, 
		plain_data.get(), plain_data_size, &plain_data_size,
		BCRYPT_BLOCK_PADDING);
	if(false == NT_SUCCESS(status))
	{
		MessageBox(nullptr, L"BCryptDecrypt() failed.", L"Error", MB_OK);
		return false;
	}

	return true;
}

bool encrypt_file(const wstring &plain_file, const wstring &cipher_file,
	BYTE *key_data, DWORD key_data_size)
{
	auto plain_file_handle = CreateFile(plain_file.c_str(), GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(INVALID_HANDLE_VALUE == plain_file_handle)
	{
		MessageBox(nullptr, L"Failed to create handle to plain file.", L"Error", MB_OK);
		return false;
	}

	auto cipher_file_handle = CreateFile(cipher_file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(INVALID_HANDLE_VALUE == cipher_file_handle)
	{
		MessageBox(nullptr, L"Failed to create handle to cipher file.", L"Error", MB_OK);
		CLOSE_HANDLE(plain_file_handle);
		return false;
	}

	while(true)
	{
		const DWORD plain_buffer_length = 10;
		BYTE plain_buffer[plain_buffer_length] = { };

		DWORD cipher_buffer_size = 0;
		unique_ptr<BYTE[]> cipher_buffer;

		DWORD bytes_read = 0;
		DWORD bytes_written = 0;

		if(FALSE == ReadFile(plain_file_handle, plain_buffer, plain_buffer_length * sizeof(plain_buffer[0]), &bytes_read, nullptr))
		{
			MessageBox(nullptr, L"ReadFile() failed.", L"Error", MB_OK);
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}

		if(0 == bytes_read)
			break;

		if(false == encrypt_data(plain_buffer, bytes_read, cipher_buffer, cipher_buffer_size, key_data, key_data_size))
		{
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}

		if(FALSE == WriteFile(cipher_file_handle, reinterpret_cast<LPCVOID>(&cipher_buffer_size), sizeof(cipher_buffer_size), &bytes_written, nullptr))
		{
			MessageBox(nullptr, L"WriteFile() failed.", L"Error", MB_OK);
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}

		if(FALSE == WriteFile(cipher_file_handle, cipher_buffer.get(), cipher_buffer_size, &bytes_written, nullptr))
		{
			MessageBox(nullptr, L"WriteFile() failed.", L"Error", MB_OK);
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}
	}

	CLOSE_HANDLE(plain_file_handle);
	CLOSE_HANDLE(cipher_file_handle);

	return true;
}

bool decrypt_file(const wstring &cipher_file, const wstring &plain_file,
	BYTE *key_data, DWORD key_data_size)
{
	auto cipher_file_handle = CreateFile(cipher_file.c_str(), GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(INVALID_HANDLE_VALUE == cipher_file_handle)
	{
		MessageBox(nullptr, L"Failed to create handle to cipher file.", L"Error", MB_OK);
		return false;
	}

	auto plain_file_handle = CreateFile(plain_file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(INVALID_HANDLE_VALUE == plain_file_handle)
	{
		MessageBox(nullptr, L"Failed to create handle to plain file.", L"Error", MB_OK);
		CLOSE_HANDLE(cipher_file_handle);
		return false;
	}

	while(true)
	{
		DWORD cipher_buffer_size = 0;
		BYTE cipher_buffer[1024] = { };

		DWORD plain_buffer_size = 0;
		unique_ptr<BYTE[]> plain_buffer;

		DWORD bytes_read = 0;
		DWORD bytes_written = 0;

		if(FALSE == ReadFile(cipher_file_handle, reinterpret_cast<LPVOID>(&cipher_buffer_size), sizeof(cipher_buffer_size), &bytes_read, nullptr))
		{
			MessageBox(nullptr, L"ReadFile() failed.", L"Error", MB_OK);
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}

		if(FALSE == ReadFile(cipher_file_handle, cipher_buffer, cipher_buffer_size, &bytes_read, nullptr))
		{
			MessageBox(nullptr, L"ReadFile() failed.", L"Error", MB_OK);
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}

		if(0 == bytes_read)
			break;

		if(false == decrypt_data(cipher_buffer, bytes_read, plain_buffer, plain_buffer_size, key_data, key_data_size))
		{
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}

		if(FALSE == WriteFile(plain_file_handle, plain_buffer.get(), plain_buffer_size, &bytes_written, nullptr))
		{
			MessageBox(nullptr, L"WriteFile() failed.", L"Error", MB_OK);
			CLOSE_HANDLE(plain_file_handle);
			CLOSE_HANDLE(cipher_file_handle);
			return false;
		}
	}

	CLOSE_HANDLE(plain_file_handle);
	CLOSE_HANDLE(cipher_file_handle);

	return true;
}

bool encrypt_directory(const wstring &plain_directory, const wstring &cipher_directory,
	BYTE *key_data, DWORD key_data_size)
{
	WIN32_FIND_DATA find_data;
	HANDLE find_handle;

	std::wstring find_path(plain_directory);
	find_path.append(L"/*");

	find_handle = FindFirstFile(find_path.c_str(), &find_data);

	while(INVALID_HANDLE_VALUE != find_handle)
	{
		if(0 != wcscmp(L".", find_data.cFileName) &&
			0 != wcscmp(L"..", find_data.cFileName) &&
			false == (FILE_ATTRIBUTE_DIRECTORY & find_data.dwFileAttributes))
		{
			std::wstring plain_file(plain_directory);
			plain_file.append(L"/").append(find_data.cFileName);

			std::wstring cipher_file(cipher_directory);
			cipher_file.append(L"/").append(find_data.cFileName);

			encrypt_file(plain_file.c_str(), cipher_file.c_str(), key_data, key_data_size);
		}

		if(FALSE == FindNextFile(find_handle, &find_data))
			break;
	}

	return true;
}

bool decrypt_directory(const wstring &cipher_directory, const wstring &plain_directory,
	BYTE *key_data, DWORD key_data_size)
{
	WIN32_FIND_DATA find_data;
	HANDLE find_handle;

	std::wstring find_path(cipher_directory);
	find_path.append(L"/*");

	find_handle = FindFirstFile(find_path.c_str(), &find_data);

	while(INVALID_HANDLE_VALUE != find_handle)
	{
		if(0 != wcscmp(L".", find_data.cFileName) &&
			0 != wcscmp(L"..", find_data.cFileName) &&
			false == (FILE_ATTRIBUTE_DIRECTORY & find_data.dwFileAttributes))
		{
			std::wstring cipher_file(cipher_directory);
			cipher_file.append(L"/").append(find_data.cFileName);

			std::wstring plain_file(plain_directory);
			plain_file.append(L"/").append(find_data.cFileName);

			decrypt_file(cipher_file.c_str(), plain_file.c_str(), key_data, key_data_size);
		}

		if(FALSE == FindNextFile(find_handle, &find_data))
			break;
	}

	return true;
}