#pragma once
#include <Windows.h>
#include <wininet.h>


typedef HINTERNET (WINAPI* _InternetOpenA)(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
);

typedef HINTERNET (WINAPI* _InternetConnectA)(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
);

typedef HINTERNET (WINAPI* _HttpOpenRequestA)(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR    *lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
);

typedef BOOL (WINAPI* _HttpSendRequestA)(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
);

typedef BOOL (WINAPI* _HttpQueryInfoA)(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
);

typedef BOOL (WINAPI* _InternetReadFile)(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI* _InternetCloseHandle)(
    HINTERNET hInternet
);

typedef DWORD (WINAPI* _GetLastError)(void);

typedef BOOL (WINAPI* _HttpEndRequestA)(
  HINTERNET hRequest,
  LPINTERNET_BUFFERSA lpBuffersOut,
  DWORD dwFlags,
  DWORD_PTR dwContext
);
