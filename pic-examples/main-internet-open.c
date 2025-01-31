#include <Windows.h>
#include "peb-lookup.h"
#include <wininet.h>
#include "func-definition.h"

int main()
{
    //variables for internet connection
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    char buffer[1024] = {0};
    DWORD bytesRead = 0;

    //stack strings
    char agent[] = {'M','y','A','g','e','n','t',0};
    char host[] = {'g','o','o','g','l','e','.','c','o','m',0};
    char method[] = {'G','E','T',0};
    char path[] = {'/',0};
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char wininet_dll_name[] = { 'w','i','n','i','n','e','t','.','d','l','l',0 };
    char internet_open_a_name[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A',0 };
    char internet_connect_a_name[] = { 'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A',0 };
    char http_open_request_a_name[] = { 'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A',0 };
    char http_send_request_a_name[] = { 'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','A',0 };
    char http_query_info_a_name[] = { 'H','t','t','p','Q','u','e','r','y','I','n','f','o','A',0 };
    char internet_read_file_name[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0 };
    char internet_close_handle_name[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0 };
    char http_end_request_name[] = {'H','t','t','p','E','n','d','R','e','q','u','e','s','t','A',0};
    char get_last_error_name[] = { 'G','e','t','L','a','s','t','E','r','r','o','r',0 };


    // resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

    //from here onwards only the _GetProcAddress function is used to retrieve function addresses

    //load wininet.dll 
    HMODULE wininet_base = _LoadLibraryA(wininet_dll_name);
    if (!wininet_base) {
        return 13;
    }

    //resolve functions from wininet dll using _GetProcAddress
    LPVOID internet_open = _GetProcAddress((HMODULE)wininet_base, (LPSTR)internet_open_a_name);
    if (!internet_open) {
        return 5;
    }

    LPVOID internet_connect = _GetProcAddress((HMODULE)wininet_base, (LPSTR)internet_connect_a_name);
    if (!internet_connect) {
        return 6;
    }

    LPVOID http_open_request = _GetProcAddress((HMODULE)wininet_base, (LPSTR)http_open_request_a_name);
    if (!http_open_request) {
        return 7;
    }

    LPVOID http_send_request = _GetProcAddress((HMODULE)wininet_base, (LPSTR)http_send_request_a_name);
    if (!http_send_request) {
        return 8;
    }

    LPVOID http_query_info = _GetProcAddress((HMODULE)wininet_base, (LPSTR)http_query_info_a_name);
    if (!http_query_info) {
        return 9;
    }

    LPVOID internet_read_file = _GetProcAddress((HMODULE)wininet_base, (LPSTR)internet_read_file_name);
    if (!internet_read_file) {
        return 10;
    }

    LPVOID internet_close_handle = _GetProcAddress((HMODULE)wininet_base, (LPSTR)internet_close_handle_name);
    if (!internet_close_handle) {
        return 11;
    }

    LPVOID http_end_request = _GetProcAddress((HMODULE)wininet_base, (LPSTR)http_end_request_name);
    if (!http_end_request) {
        return 14;
    }

    LPVOID get_last_error = _GetProcAddress((HMODULE)base, (LPSTR)get_last_error_name);
    if (!get_last_error) {
        return 12;
    }

    

    // Function definitions from wininet.dll
    _InternetOpenA InternetOpenA = (HINTERNET(WINAPI*)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD))internet_open;
    _InternetConnectA InternetConnectA = (HINTERNET(WINAPI*)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR))internet_connect;
    _HttpOpenRequestA HttpOpenRequestA = (HINTERNET(WINAPI*)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR))http_open_request;
    _HttpSendRequestA HttpSendRequestA = (BOOL(WINAPI*)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD))http_send_request;
    _HttpQueryInfoA HttpQueryInfoA = (BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD))http_query_info;
    _InternetReadFile InternetReadFile = (BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD))internet_read_file;
    _InternetCloseHandle InternetCloseHandle = (BOOL(WINAPI*)(HINTERNET))internet_close_handle;
    _GetLastError GetLastError = (DWORD(WINAPI*)(void))get_last_error;
    _HttpEndRequestA HttpEndRequestA = (BOOL(WINAPI*)(HINTERNET, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR))http_end_request;

    
    // Initialize WinINet
    hInternet = InternetOpenA(agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        return 1;
    }

    // Connect to google.com
    hConnect = InternetConnectA(hInternet, host, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (hConnect == NULL) {
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Open request
    hRequest = HttpOpenRequestA(hConnect, method, path, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (hRequest == NULL) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Send request
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Check status code
    if (!HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }

    //i do not really care about the status code for now
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
    // do nothing
    }


    // Clean up
    if (!HttpEndRequestA(hRequest,NULL,0,0)){

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return 0;
}