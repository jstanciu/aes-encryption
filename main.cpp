// main.cpp : Defines the entry point for the application.
//

#include "main.h"
#include "crypt.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <memory>
using std::unique_ptr;

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include <Shlobj.h>

using std::wstring;

// For text box
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

HWND Window;
HWND Input_Text_Box;
HWND Output_Text_Box;
HWND Key_Text_Box;

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// TODO: Place code here.

	// Initialize global strings
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadStringW(hInstance, IDC_AES256, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if(!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_AES256));

	MSG msg;

	// Main message loop:
	while(GetMessage(&msg, nullptr, 0, 0))
	{
		if(!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_AES256));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = nullptr;//MAKEINTRESOURCEW(IDC_AES256);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance; // Store instance handle in our global variable

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, 800, 150, nullptr, nullptr, hInstance, nullptr);

	if(!hWnd)
	{
		return FALSE;
	}

	Window = hWnd;

	//
	// Create custom controls
	//

	// Start encrypt/decrypt buttons.
	const auto button_class = L"button";
	auto button_start_x = 10;
	auto button_start_y = 10;
	auto button_buffer_y = 10;
	auto button_width = 70;
	auto button_height = 40;
	auto button_styles = WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON;

	CreateWindow(button_class, L"Encrypt", button_styles,
		button_start_x,
		button_start_y,
		button_width,
		button_height,
		hWnd, reinterpret_cast<HMENU>(IDM_ENCRYPT), reinterpret_cast<HINSTANCE>(GetWindowLong(hWnd, GWL_HINSTANCE)), nullptr);

	CreateWindow(button_class, L"Decrypt", button_styles,
		button_start_x,
		button_start_y + button_buffer_y + button_height,
		button_width,
		button_height,
		hWnd, reinterpret_cast<HMENU>(IDM_DECRYPT), reinterpret_cast<HINSTANCE>(GetWindowLong(hWnd, GWL_HINSTANCE)), nullptr);

	// Start text box.
	const auto text_class = L"edit";
	auto text_start_x = button_start_x + button_width + 50;
	auto text_start_y = button_start_y;
	auto text_buffer_y = 10;
	auto text_width = 640;
	auto text_height = 20;
	auto text_styles = WS_CHILD | WS_VISIBLE;

	Input_Text_Box = CreateWindowEx(WS_EX_CLIENTEDGE, text_class, L"Input File/Directory", text_styles,
		text_start_x,
		text_start_y,
		text_width,
		text_height,
		hWnd, nullptr, nullptr, nullptr);

	Output_Text_Box = CreateWindowEx(WS_EX_CLIENTEDGE, text_class, L"Output File/Directory", text_styles,
		text_start_x,
		text_start_y + text_buffer_y + text_height,
		text_width,
		text_height,
		hWnd, nullptr, nullptr, nullptr);

	Key_Text_Box = CreateWindowEx(WS_EX_CLIENTEDGE, text_class, L"32 character alphanumeric key", text_styles,
		text_start_x,
		text_start_y + 2*text_buffer_y + 2*text_height,
		text_width,
		text_height,
		hWnd, nullptr, nullptr, nullptr);

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	return TRUE;
}

template<size_t size> 
bool get_user_input(std::wstring &input_text, std::wstring &output_text, char (&key_text)[size])
{
	unique_ptr<wchar_t[]> input;
	unique_ptr<wchar_t[]> output;

	int input_length = GetWindowTextLength(Input_Text_Box);
	int output_length = GetWindowTextLength(Output_Text_Box);
	int key_length = GetWindowTextLength(Key_Text_Box);

	input.reset(new wchar_t[input_length + 1]);
	output.reset(new wchar_t[output_length + 1]);

	// Verify key length.
	if(size - 1 != key_length)
	{
		wchar_t message[256] = { };
		swprintf_s(message, L"Key length is not 32 bytes. Length:%d", key_length);
		MessageBox(Window, message, L"Key Error", MB_OK);
		return false;
	}

	// Get user input.
	GetWindowText(Input_Text_Box, input.get(), input_length + 1);
	GetWindowText(Output_Text_Box, output.get(), output_length + 1);
	GetWindowTextA(Key_Text_Box, key_text, key_length + 1);

	// Check input path.
	if(FALSE == PathFileExists(input.get()))
	{
		MessageBox(Window, L"Input path does not exist.", L"Input Error", MB_OK);
		return false;
	}

	// Verify key is alphanumeric.
	for(int i = 0; i < sizeof(key_text) - 1; ++i)
	{
		if(false == isalnum(key_text[i]))
		{
			MessageBox(Window, L"Key is not alphanumeric.", L"Key Error", MB_OK);
			return false;
		}
	}

	input_text.assign(input.get());
	output_text.assign(output.get());

	return true;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		// Parse the menu selections:
		switch(wmId)
		{
		case IDM_ENCRYPT:
		case IDM_DECRYPT:
		{
			wstring input, output;
			char key[33] = { };

			if(false == get_user_input(input, output, key))
				break;

			if(input == output)
			{
				MessageBox(Window, L"Input and Output cannot be the same.", L"Input/Output Error", MB_OK);
				break;
			}

			if(FALSE == PathIsDirectory(input.c_str()))
			{
				if(FALSE != PathIsDirectory(output.c_str()))
				{
					MessageBox(Window, L"Output is a directory while input is a file.", L"Input/Output Error", MB_OK);
					break;
				}

				unique_ptr<wchar_t[]> output_directory(new (std::nothrow) wchar_t[output.length() + 1]);
				if(nullptr == output_directory.get())
				{
					MessageBox(Window, L"Failed to allocate memory", L"Output Error", MB_OK);
					break;
				}

				wcscpy_s(output_directory.get(), output.length() + 1, output.c_str());

				if(FALSE == PathRemoveFileSpec(output_directory.get()))
				{
					MessageBox(Window, L"Failed to get output directory", L"Output Error", MB_OK);
					break;
				}

				if(FALSE == PathFileExists(output_directory.get()))
				{
					if(ERROR_SUCCESS != SHCreateDirectory(Window, output_directory.get()))
					{
						MessageBox(Window, L"Failed to create output directory.", L"Output Error", MB_OK);
						break;
					}
				}

				if(IDM_ENCRYPT == wmId)
					encrypt_file(input, output, reinterpret_cast<BYTE*>(key), sizeof(key) - 1);
				else
					decrypt_file(input, output, reinterpret_cast<BYTE*>(key), sizeof(key) - 1);
			}
			else
			{
				if(FALSE == PathIsDirectory(output.c_str()))
				{
					MessageBox(Window, L"Input is a directory while output is a file.", L"Input/Output Error", MB_OK);
					break;
				}

				if(FALSE == PathFileExists(output.c_str()))
				{
					if(ERROR_SUCCESS != SHCreateDirectory(Window, output.c_str()))
					{
						MessageBox(Window, L"Failed to create output directory.", L"Output Error", MB_OK);
						break;
					}
				}

				if(IDM_ENCRYPT == wmId)
					encrypt_directory(input, output, reinterpret_cast<BYTE*>(key), sizeof(key) - 1);
				else
					decrypt_directory(input, output, reinterpret_cast<BYTE*>(key), sizeof(key) - 1);
			}

			break;
		}

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code that uses hdc here...
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch(message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if(LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
