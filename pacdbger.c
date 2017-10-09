/* pacdbger
This program insists the same capability as the windows OS, and printing the position where error ocured!

***
MS should make jsproxy to a standalone pac debugging tool :)

***
winhttp.dll <---> {jsproxy.dll} <---> jscript.dll
wininet.dll: useful functions.

***
autoprox (v2.44) is open-sourced: https://github.com/pierrecoll/autoprox
But it still doesn't feedback js errors. It just use functions of 'jsproxy.dll', and can't catch them.
*
Maybe we should implement the 'jsproxy.dll', or hack it :)
*
Build-in functions (for pac) and 'InternetGetProxyInfo' are in 'jsproxy.dll'. And the 'InternetGetProxyInfo' should be hacked! We collect the 'IActiveScriptError' here.
*
How to always keep the same build-in functions with OS?
Compiled as native code, any exports?

***
Learn 'windows wininet source code': http://www.codeforge.com/read/121016/jsproxy.cpp__html
InternetInitializeAutoProxyDll ---> {InternetGetProxyInfo} ---> InternetDeInitializeAutoProxyDll

We know the 'jsproxy' dll initializes a global 'CScriptSite' as 'g_ScriptSite',
'g_ScriptSite' initializes a private 'CJSProxy' as 'm_punkJSProxy', and 'm_punkJSProxy'
contains the private 'm_strings' that holds the build-in functions name.

The 'g_ScriptSite' is binded to 'IActiveScriptSite' by calling 'IActiveScript::SetScriptSite',
then invoked by calling 'IActiveScript::SetScriptState', 'IActiveScript::GetScriptDispatch',
'IDispatch::GetIDsOfNames' gets private 'm_Scriptdispid', and run 'IDispatch->Invoke(m_Scriptdispid, ...)'.

So, seems if we can get the global 'g_ScriptSite' and implement the 'InternetGetProxyInfo', it is possible!
We need confirm this by IDA :)

...

It is evolving ... there is a new construction (v8 ~ v11):
A global 'g_pwszAutoProxyScriptBuffer' set by 'InternetInitializeAutoProxyDll'; and '_CreateScriptSite' is called by 'InternetGetProxyInfo'.

Good news:) There are '*Ex' stub functions keep the expected flow!
g_pAutoProxyHelperAPIs = (struct AUTO_PROXY_HELPER_APIS *)&g_DefaultAutoProxyHelperAPIs;

LIBRARY "JSProxy.dll"
EXPORTS
InternetInitializeAutoProxyDll@20
InternetDeInitializeAutoProxyDll@8
InternetGetProxyInfo@24
InternetInitializeAutoProxyDllEx@24
InternetDeInitializeAutoProxyDllEx@4
InternetGetProxyInfoEx@16

v8.00.6001.18702: http://xpdll.nirsoft.net/jsproxy_dll.html
InternetDeInitializeAutoProxyDll
InternetDeInitializeExAutoProxyDll
InternetGetProxyInfo
InternetInitializeAutoProxyDll
InternetInitializeExAutoProxyDll

!!!
You can get the w2k's autoprox code :) But the API has changed.
http://read.pudn.com/downloads3/sourcecode/windows/248345/win2k/private/inet/wininet/inc/autoprox.hxx__.htm
http://icerote.net/doc/library/programming/source/SOURCE.CODE.MICROSOFT.WINDOWS.2000.AND.NT4-BTDE/win2k/private/inet/wininet/handles/autoprox.cxx

'InternetInitializeAutoProxyDllEx' returns the ' CScriptSite' created?

Let's explorer it ...
:)


???
2 'InternetInitializeAutoProxyDll':
https://msdn.microsoft.com/en-us/library/windows/desktop/aa385093.aspx
'InternetInitializeAutoProxyDll@4' in 'wininet.dll', but not the left 2 functions;
'InternetInitializeAutoProxyDll@20' in 'jsproxy.dll';
'InternetInitializeAutoProxyDllEx@24' in 'jsproxy.dll';
See the 2nd one (IDA could guess params wrong):
Same name, the 1st one is declared, but the 2nd one not, so must be called dynamically.

?
OS service 'WinHttpAutoProxySvc' calls 'winhttp.dll', that runs extra system preparation.

---
We want not only the result, but also to debug, so go deep into the following.

InternetGetProxyInfo:
https://github.com/reactos/reactos/blob/31b47ad45e6384dd538ebfee33c4829945cf2eee/reactos/dll/win32/jsproxy/main.c#L634
https://msdn.microsoft.com/en-us/library/windows/desktop/aa384726(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa385093(v=vs.85).aspx

jsproxy:
https://github.com/reactos/reactos/blob/master/reactos/dll/win32/jsproxy/main.c
https://github.com/wine-mirror/wine/tree/master/dlls/jsproxy
http://www.codeforge.com/read/121016/jsproxy.cpp__html

jsproxy.dll:
CPU Disasm
Address   Hex dump          Command                                  Comments
59312BCE  |.  C741 14 782C3 MOV DWORD PTR DS:[ECX+14],59312C78       ; UNICODE "isPlainHostName"
59312BD5  |.  C741 18 982C3 MOV DWORD PTR DS:[ECX+18],59312C98       ; UNICODE "dnsDomainIs"
59312BDC  |.  C741 1C B02C3 MOV DWORD PTR DS:[ECX+1C],59312CB0       ; UNICODE "localHostOrDomainIs"
59312BE3  |.  C741 20 D82C3 MOV DWORD PTR DS:[ECX+20],59312CD8       ; UNICODE "isResolvable"
59312BEA  |.  C741 24 F42C3 MOV DWORD PTR DS:[ECX+24],59312CF4       ; UNICODE "isInNet"
59312BF1  |.  C741 28 042D3 MOV DWORD PTR DS:[ECX+28],59312D04       ; UNICODE "dnsResolve"
59312BF8  |.  C741 2C 1C2D3 MOV DWORD PTR DS:[ECX+2C],59312D1C       ; UNICODE "myIpAddress"
59312BFF  |.  C741 30 342D3 MOV DWORD PTR DS:[ECX+30],59312D34       ; UNICODE "dnsDomainLevels"
59312C06  |.  C741 34 542D3 MOV DWORD PTR DS:[ECX+34],59312D54       ; UNICODE "shExpMatch"
59312C0D  |.  C741 38 6C2D3 MOV DWORD PTR DS:[ECX+38],59312D6C       ; UNICODE "weekdayRange"
59312C14  |.  C741 3C 882D3 MOV DWORD PTR DS:[ECX+3C],59312D88       ; UNICODE "dateRange"
59312C1B  |.  C741 40 9C2D3 MOV DWORD PTR DS:[ECX+40],59312D9C       ; UNICODE "timeRange"
59312C22  |.  C741 44 B02D3 MOV DWORD PTR DS:[ECX+44],59312DB0       ; UNICODE "alert"
59312C29  |.  C741 48 BC2D3 MOV DWORD PTR DS:[ECX+48],59312DBC       ; UNICODE "isResolvableEx"
59312C30  |.  C741 4C DC2D3 MOV DWORD PTR DS:[ECX+4C],59312DDC       ; UNICODE "isInNetEx"
59312C37  |.  C741 50 F02D3 MOV DWORD PTR DS:[ECX+50],59312DF0       ; UNICODE "dnsResolveEx"
59312C3E  |.  C741 54 0C2E3 MOV DWORD PTR DS:[ECX+54],59312E0C       ; UNICODE "myIpAddressEx"
59312C45  |.  C741 58 282E3 MOV DWORD PTR DS:[ECX+58],59312E28       ; UNICODE "sortIpAddressList"
59312C4C  |.  C741 5C 4C2E3 MOV DWORD PTR DS:[ECX+5C],59312E4C       ; UNICODE "getClientVersion"
MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/aa383907.aspx

AutoProxyHelperVtbl:
wininet.h

IActiveScriptParse_ParseScriptText:
https://docs.microsoft.com/en-us/scripting/winscript/reference/iactivescriptparse-parsescripttext

IActiveScriptParse:
activscp.idl
activscp.h

IDispatch_Invoke:

IActiveScriptError:
https://docs.microsoft.com/en-us/scripting/winscript/reference/iactivescripterror
IActiveScriptError::GetExceptionInfo      Retrieves information about an error.
IActiveScriptError::GetSourcePosition     Retrieves the location in the source code where an error occurred.
IActiveScriptError::GetSourceLineText     Retrieves the line in the source file where an error occurred.

***
https://docs.microsoft.com/en-us/scripting/winscript/reference/iactivescriptsite-onscripterror
CScriptSite::OnScriptError(IActiveScriptError *)

---
https://github.com/citizenmatt/SimpleActiveScriptHost/blob/master/src/SimpleActiveScriptHost/ScriptSite.h

pdb:
---
AUTO_PROXY_HELPER_APIS::GetIPAddress(char *,ulong *)
AUTO_PROXY_HELPER_APIS::GetIPAddressExW(ushort *,ulong *)
AUTO_PROXY_HELPER_APIS::GetIPAddressW(ushort *,ulong *)
AUTO_PROXY_HELPER_APIS::IsInNetExW(ushort *,ushort *)
AUTO_PROXY_HELPER_APIS::IsInNetW(ushort *,ushort *,ushort *)
AUTO_PROXY_HELPER_APIS::IsResolvableExW(ushort *)
AUTO_PROXY_HELPER_APIS::IsResolvableW(ushort *)
AUTO_PROXY_HELPER_APIS::ResolveHostName(char *,char *,ulong *)
AUTO_PROXY_HELPER_APIS::ResolveHostNameExW(ushort *,ushort *,ulong *)
AUTO_PROXY_HELPER_APIS::ResolveHostNameW(ushort *,ushort *,ulong *)
AUTO_PROXY_HELPER_APIS::SortIpListW(ushort *,ushort *,ulong *)

---
CJSProxy::AddRef(void)
CJSProxy::GetIDsOfNames(_GUID const &,ushort * *,uint,ulong,long *)
CJSProxy::GetTypeInfo(uint,ulong,ITypeInfo * *)
CJSProxy::GetTypeInfoCount(uint *)
CJSProxy::Invoke(long,_GUID const &,ulong,ushort,tagDISPPARAMS *,tagVARIANT *,tagEXCEPINFO *,uint *)
CJSProxy::QueryInterface(_GUID const &,void * *)
CJSProxy::Release(void)
CJSProxy::`scalar deleting destructor'(uint)
CJSProxy::dnsDomainIs(ushort *,ushort *,tagVARIANT *)
CJSProxy::dnsDomainLevels(ushort *,tagVARIANT *)
CJSProxy::dnsResolve(ushort *,tagVARIANT *)
CJSProxy::dnsResolveEx(ushort *,tagVARIANT *)
CJSProxy::getClientVersion(tagVARIANT *)
CJSProxy::isInNet(ushort *,ushort *,ushort *,tagVARIANT *)
CJSProxy::isInNetEx(ushort *,ushort *,tagVARIANT *)
CJSProxy::isPlainHostName(ushort *,tagVARIANT *)
CJSProxy::isResolvable(ushort *,tagVARIANT *)
CJSProxy::isResolvableEx(ushort *,tagVARIANT *)
CJSProxy::localHostOrDomainIs(ushort *,ushort *,tagVARIANT *)
CJSProxy::myIpAddress(tagVARIANT *)
CJSProxy::myIpAddressEx(tagVARIANT *)
CJSProxy::shExpMatch(ushort *,ushort *,tagVARIANT *)
CJSProxy::sortIpAddressList(ushort *,tagVARIANT *)
CJSProxy::weekdayRange(ushort *,ushort *,ushort *,tagVARIANT *)

---
CScriptSite::AddRef(void)
CScriptSite::DeInit(void)
CScriptSite::GetDocVersionString(ushort * *)
CScriptSite::GetItemInfo(ushort const *,ulong,IUnknown * *,ITypeInfo * *)
CScriptSite::GetSecurityId(uchar *,ulong *,ulong)
CScriptSite::Init(AUTO_PROXY_HELPER_APIS *,ushort const *,int,long (*)(ushort *,tagVARIANT *),int)
CScriptSite::OnLeaveScript(void)
CScriptSite::OnScriptError(IActiveScriptError *)
CScriptSite::OnScriptTerminate(tagVARIANT const *,tagEXCEPINFO const *)
CScriptSite::OnStateChange(tagSCRIPTSTATE)
CScriptSite::ProcessUrlAction(ulong,uchar *,ulong,uchar *,ulong,ulong,ulong)
CScriptSite::QueryContinue(void)
CScriptSite::QueryCustomPolicy(_GUID const &,uchar * *,ulong *,uchar *,ulong,ulong)
CScriptSite::QueryInterface(_GUID const &,void * *)
CScriptSite::QueryService(_GUID const &,_GUID const &,void * *)
CScriptSite::Release(void)
CScriptSite::RunScript(ushort const *,ushort const *,ushort * *)
CScriptSite::`scalar deleting destructor'(uint)

*/

// At last we got the following codes achieving the goal!

// x86: cl.exe /Os /MD *.c Ole32.lib Version.lib
// x64: cl.exe /Os /MD *.c Ole32.lib Version.lib bufferoverflowU.lib

#define _WIN32_WINNT 0x0501 // XP, 0x0601: Windows 7. structs for API

#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <locale.h>

#include <windows.h>
#include <ole2.h>
#include <wininet.h>
#include <sys/stat.h>


typedef AutoProxyHelperFunctions AUTO_PROXY_HELPER_APIS;
typedef AutoProxyHelperFunctions AUTO_PROXY_HELPER_APIS_EX;

// CJSProxy::Init
typedef struct CJSProxy { // :IDispatch
    IDispatchVtbl *pIDispatchVtbl; // &CJSProxy::`vftable';
    DWORD dwRefCount;
    BOOL bDestroyable; // 0 ?
    BOOL bInitialized;
    AUTO_PROXY_HELPER_APIS* lpAutoProxyCallbacks;  // g_AutoProxyHelperAPIs
    wchar_t *v6; // L"isPlainHostName";
    wchar_t *v7; // L"dnsDomainIs";
    wchar_t *v8; // L"localHostOrDomainIs";
    wchar_t *v9; // L"isResolvable";
    wchar_t *v10; // L"isInNet";
    wchar_t *v11; // L"dnsResolve";
    wchar_t *v12; // L"myIpAddress";
    wchar_t *v13; // L"dnsDomainLevels";
    wchar_t *v14; // L"shExpMatch";
    wchar_t *v15; // L"weekdayRange";
    wchar_t *v16; // L"dateRange";
    wchar_t *v17; // L"timeRange";
    wchar_t *v18; // L"alert";
    wchar_t *v19; // L"isResolvableEx";
    wchar_t *v20; // L"isInNetEx";
    wchar_t *v21; // L"dnsResolveEx";
    wchar_t *v22; // L"myIpAddressEx";
    wchar_t *v23; // L"sortIpAddressList";
    wchar_t *v24; // L"getClientVersion";
    BOOL bUsingExtendedVTable;  // g_fUsingExtendedVTable
    DWORD v26; // a3
    BOOL bUsingUnicodeVTable;   // g_fUsingUnicodeVTable
} CJSProxy;

// MSVC: include\activdbg.h
// mingw: N
// CScriptSite::CScriptSite, CScriptSite::Init
#ifdef _MSC_VER
    #include <activdbg.h>
#else
    #include <activscp.h>
    #include <urlmon.h>
#endif
// ICScriptSiteVtbl is the first 4 lpVtbl
typedef struct CScriptSite { // :IActiveScriptSite
    IActiveScriptSiteVtbl   *pIActiveScriptSiteVtbl; //include\activscp.h
    IServiceProviderVtbl    *pIServiceProviderVtbl;  //include\servprov.h
    IActiveScriptSiteInterruptPollVtbl  *pIActiveScriptSiteInterruptPollVtbl; //include\activscp.h
    IInternetHostSecurityManagerVtbl    *pIInternetHostSecurityManagerVtbl;   //include\urlmon.h
    BOOL    bInitialized;
    DWORD   s_dwJScriptEngineRefCount;
    IActiveScript   *pIJScript;
#ifdef _WIN64
    IActiveScriptParse64    *pIActiveScriptParse;
#else
    IActiveScriptParse32    *pIActiveScriptParse;
#endif
    CJSProxy    *pCJSProxy;     // :IDispatch
    IDispatch   *pJScriptDisp;  //!!!
    DISPID      ScriptDispId;   //"FindProxyForURL"
    DISPID      ScriptDispIdEx; //"FindProxyForURLEx"; -1, if not exists.
    BOOL    bWinsockInitialized;
    DWORD v14;  //s_hJScriptModuleHandle? No!
    DWORD   dwTickCount;
    DWORD v16;  //s_pfnDllGetClassObject? No!
} CScriptSite;

/* other data
AUTO_PROXY_HELPER_APIS*    g_DefaultAutoProxyHelperAPIs;
AUTO_PROXY_HELPER_APIS*    g_pAutoProxyHelperAPIs = a4;
BOOL    g_fUsingExtendedVTable = v8;
BOOL    g_fUsingUnicodeVTable = v7 == 196608;
wchar_t *g_pwszAutoProxyScriptBuffer = pv;

HMODULE s_hJScriptModuleHandle;
FARPROC s_pfnDllGetClassObject;

jproxy.pdb PUBLICS:
?g_rgWppEnabledFlagsPerLevel@@3PAT_tagWppEnabledFlags@@A
?g_pAutoProxyHelperAPIs@@3PAVAUTO_PROXY_HELPER_APIS@@A
?g_fUsingExtendedVTable@@3HA
?g_pwszAutoProxyScriptBuffer@@3PAGA
?g_csNetworkStatus@@3VWxCriticalSection@@A
?g_csAutoProxyLock@@3U_RTL_CRITICAL_SECTION@@A
?g_fUsingUnicodeVTable@@3HA
?g_WxSavedExceptionRecord@@3U_EXCEPTION_RECORD@@A
?g_DefaultAutoProxyHelperAPIs@@3VAUTO_PROXY_HELPER_APIS@@A
?g_WxSavedContext@@3U_CONTEXT@@A
?g_strNetworkStatusDialUpConnectionName@@3VCWxString@@A
?g_csDllRefRelease@@3VWxCriticalSection@@A
?g_csDllRef@@3VWxCriticalSection@@A
*/


#define _IN_
#define _OUT_
#define _IN_OPT_
#define _OUT_OPT_


/* history:
I don't know which exact verion is the watershed :D

'DownloadedTempFile' path in wchar_t:
'v11.0.9600.18792'
'v10.0.9200.16537'
InternetInitializeAutoProxyDllEx@24
InternetDeInitializeAutoProxyDllEx@4
InternetGetProxyInfoEx@16

'DownloadedTempFile' path in char:
'v9.0.8112.16450'
InternetInitializeAutoProxyDllEx@24
InternetDeInitializeAutoProxyDllEx@4
InternetGetProxyInfoEx@16

Holly shit, different params:
'v8.0.7601.19104'
'v8.0.7601.18660'
InternetGetProxyInfo@24
InternetInitializeAutoProxyDllEx@24
InternetDeInitializeAutoProxyDllEx@4
InternetGetProxyInfoEx@28   !!! <<<^^^---

https://en.wikipedia.org/wiki/Internet_Explorer_8#Release_history

!!! Different API name and process, don't have 'InternetGetProxyInfoEx' etc.
'v8.0.6001.18702'
'v7.0.6001.18639'
InternetInitializeExAutoProxyDll(x):
InternetInitializeExAutoProxyDll@4
InternetDeInitializeExAutoProxyDll@4
!!! ---


!!!
Don't have Ex APIs:
'v6.0.2900.5512'
'v6.0.2900.2180'

others: https://en.wikipedia.org/wiki/Internet_Explorer#History
*/

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385093.aspx
// Initializing the COM yourself!
// We declare the 3(4) APIs, but may not use them, just keep the types in mind when using them :)
// v11/v10: LPWSTR; v8/v9: LPSTR
typedef int (CALLBACK *pfnInternetInitializeAutoProxyDllEx)
(
    _IN_        DWORD dwReserved,               // not used
    _IN_        DWORD a2,  // CJSProxy.v26, ?
    _OUT_       void *lptszDownloadedTempFile,  // v11/v10: LPWSTR; v8/v9: LPSTR
    _IN_OPT_    VARIANT *varScript,     // the script text; oaidl.h.
                                        // v11/v10: vt = 8, v9/v8: vt = 12;
                                        // wReserved1 = 0, wReserved2 wReserved3 is bstrVal
                                        // bstrVal != 0  is the contents
    _OUT_       CScriptSite **ppCScriptSite,    // CScriptSite::CScriptSite(V9)
    _OUT_OPT_   void *lptAutoProxyScriptBuffer  // v11/v10: LPWSTR; v8/v9: LPSTR
);

// v11/v10: LPWSTR; v9: LPSTR
typedef int (CALLBACK *pfnInternetGetProxyInfoEx)
(
    _IN_  CScriptSite *pCScriptSite,
    _IN_  void    *lptszUrl,
    _IN_  void    *lptszUrlHostName,
    _OUT_ void    *lplptszProxyHostName	
);

// v8
typedef int (CALLBACK *pfnInternetGetProxyInfoEx_Stub)
(
    _IN_  CScriptSite *pCScriptSite,
    _IN_  LPCSTR  lpszUrl,
    _IN_  DWORD   dwUrlLength,
    _IN_  LPSTR   lpszUrlHostName,
    _IN_  DWORD   dwUrlHostNameLength,
    _OUT_ LPSTR   *lplpszProxyHostName,
    _OUT_ LPDWORD lpdwProxyHostNameLength
);

typedef void (CALLBACK *pfnInternetDeInitializeAutoProxyDllEx)(CScriptSite **ppCScriptSite);


//
FARPROC WINAPI GetProcAddress_FBK(HMODULE hMod, char *funcn) {
    FARPROC pAddress;
    pAddress = GetProcAddress(hMod, funcn);
    if (!pAddress) {
        fprintf(stderr, "GetProcAddress failed to find %s with error: %d\n", GetLastError() );
    }
    return pAddress;
}

// use _getmbcp()
size_t cs_to_utf16(UINT cp_in, const char *str_in, wchar_t **str_w) {
    size_t len_w;
    //
    len_w = MultiByteToWideChar(cp_in, 0, str_in, -1, NULL, 0);
    if (len_w == 0) {return 0;}
    *str_w = calloc(len_w, sizeof(wchar_t));
    len_w = MultiByteToWideChar(cp_in, 0, str_in, -1, *str_w, len_w);
    return len_w - 1;
}

char* gethost(char* url) {
    char *p1, *p2, *p = NULL;
    size_t n;
    p1 = strstr(url, "://");
    if (p1) {
        p1 = p1 + 3;
        p2 = strstr(p1, "/");
        if (p2 <= p1) {
            p2 = url + strlen(url);
        }
        n = p2 - p1;
        p = calloc(1, n + sizeof(char));
        p = strncpy(p, p1, n);
    }
    return p;
}

_TCHAR* GetFileVersionStr(_TCHAR *strFileName)
{
    DWORD dwVerInfoSize;
    char *vBuffer;
    LPVOID lpResult = NULL;
    //
    dwVerInfoSize = GetFileVersionInfoSize(strFileName, NULL);
    if (dwVerInfoSize > 0) {
        vBuffer = calloc(1, dwVerInfoSize);
        if (GetFileVersionInfo(strFileName, 0, dwVerInfoSize, vBuffer)) {
            LPDWORD lang;
            UINT uLen = 0;
            LPVOID lpResult_1;
            _TCHAR strSubBlock[40] = {0}; //\StringFileInfo\12341234\ProductVersion
            //
            if (VerQueryValue(vBuffer, "\\VarFileInfo\\Translation", (void**)&lang, &uLen)) {
                _stprintf(strSubBlock, "\\StringFileInfo\\%04x%04x\\ProductVersion", LOWORD(lang[0]), HIWORD(lang[0]));
            }
            if (VerQueryValue(vBuffer, strSubBlock, (LPVOID*)&lpResult_1, &uLen))
            {
                lpResult = realloc(lpResult, uLen + sizeof(_TCHAR));
                memcpy(lpResult, lpResult_1, uLen);
            }
        }
        free(vBuffer);
    }
    //
    return lpResult;
}

int GetVersionArray(_TCHAR *strVersion, int **iaVersion)
{
    _TCHAR *p;
    int n;
    //
    if (!*strVersion) return 0;
    p = strVersion;
    n = 0;
    while (p) {
        n++;
        *iaVersion = realloc(*iaVersion, n * sizeof(int));
        (*iaVersion)[n-1] = _tstoi(p);
        p = _tcsstr(p, _T("."));
        if (p) p = p + 1;
    }
    return n;
}


// More hacks? Refer: https://docs.microsoft.com/en-us/scripting/winscript/windows-script-interfaces
HRESULT STDMETHODCALLTYPE CScriptSite_OnScriptError_Hack(CScriptSite *pCScriptSite, IActiveScriptError *pIActiveScriptError)
{
    IActiveScriptErrorVtbl *IActiveScriptError_lpVtbl;
    EXCEPINFO ExcepInfo;
    DWORD   dwSourceContext = 0;
    ULONG   ulLineNumber    = 0;
    LONG    ichCharPosition = 0;
    HRESULT hr;
    //
    memset(&ExcepInfo, 0, sizeof(EXCEPINFO));
    //
    IActiveScriptError_lpVtbl = pIActiveScriptError->lpVtbl;
    hr = IActiveScriptError_lpVtbl->GetSourcePosition(pIActiveScriptError, &dwSourceContext, &ulLineNumber, &ichCharPosition);
    if (hr == S_OK) {
        wprintf(L"(%d, %d)", ulLineNumber + 1, ichCharPosition + 1);
    }
    hr = IActiveScriptError_lpVtbl->GetExceptionInfo(pIActiveScriptError, &ExcepInfo);
    if (hr == S_OK) {
        wprintf(L": %s\n", ExcepInfo.bstrDescription); // ? It's the str pointer part of the whole BSTR
        // free BSTR
        if (ExcepInfo.bstrHelpFile) SysFreeString(ExcepInfo.bstrHelpFile);
        if (ExcepInfo.bstrDescription) SysFreeString(ExcepInfo.bstrDescription);
        if (ExcepInfo.bstrSource) SysFreeString(ExcepInfo.bstrSource);
    }
    return 0;
}


IActiveScriptSiteVtbl   IActiveScriptSiteVtbl_hack;  // keep it, global
IActiveScriptSiteVtbl   *pIActiveScriptSiteVtbl_bak; // for releasing

CScriptSite* hackCScriptSite(CScriptSite *pCScriptSite)
{
    // key: *(pCScriptSite->pIActiveScriptSiteVtbl)
    // Hack it! Can't be overwrited, avoided by section access property! And maybe not safe.
    // Let's store it locally
    pIActiveScriptSiteVtbl_bak = pCScriptSite->pIActiveScriptSiteVtbl;
    IActiveScriptSiteVtbl_hack = *(pCScriptSite->pIActiveScriptSiteVtbl);
    IActiveScriptSiteVtbl_hack.OnScriptError = (void*)CScriptSite_OnScriptError_Hack;
    pCScriptSite->pIActiveScriptSiteVtbl = &IActiveScriptSiteVtbl_hack;
    return pCScriptSite;
}

CScriptSite* restoreCScriptSite(CScriptSite *pCScriptSite)
{
    // for releasing
    pCScriptSite->pIActiveScriptSiteVtbl = pIActiveScriptSiteVtbl_bak;
    return pCScriptSite;
}

int InternetGetProxyInfoEx_X_dbg(CScriptSite *pCScriptSite, void *lpAutoProxyScriptBuffer,
    FARPROC pInternetGetProxyInfoEx, void *purl, DWORD url_len, void *phost, DWORD host_len, void **ppproxy, LPDWORD proxy_len)
{
    int ret;
    LARGE_INTEGER c1, c2, Freq;
    QueryPerformanceFrequency(&Freq);
    //
    hackCScriptSite(pCScriptSite);
    // 'ParseScriptText' AGAIN using new OnScriptError hack
    if ( pCScriptSite->pIActiveScriptParse->lpVtbl->ParseScriptText(pCScriptSite->pIActiveScriptParse,
            lpAutoProxyScriptBuffer, NULL, NULL, NULL, 0, 0, SCRIPTTEXT_ISEXPRESSION|SCRIPTTEXT_ISVISIBLE, NULL, NULL)
        != S_OK ) {return 1;}
    //
    QueryPerformanceCounter(&c1);
    if (url_len) {
        ret = pInternetGetProxyInfoEx(pCScriptSite, purl, url_len, phost, host_len, ppproxy, proxy_len); // Stub
    }
    else {
        ret = pInternetGetProxyInfoEx(pCScriptSite, purl, phost, ppproxy);
    }
    if (ret) {
        fprintf(stderr, "InternetGetProxyInfoEx failed: %d\n", ret);
        return 1;
    }
    QueryPerformanceCounter(&c2);
    printf(pCScriptSite->ScriptDispIdEx == -1 ? "FindProxyForURL" : "FindProxyForURLEx");
    printf(": %.12f(s)\n", (float)(c2.QuadPart-c1.QuadPart)/Freq.QuadPart);
    //
    restoreCScriptSite(pCScriptSite);
    return 0;
}

static size_t read_file(FILE* fp, unsigned char** output) {
    size_t smart_size, count;
    size_t length = 0;
    //make it faster
    if (!fp) { //incase
        return 0;
    }
    else if (fp == stdin) {
        smart_size = stdin->_bufsiz;
    }
    else { //unreliable for stdin!
        struct stat filestats;
        int fd = fileno(fp);
        fstat(fd, &filestats);
        smart_size = filestats.st_size + 1; // +1 to get EOF, BIG file
    }
    //
    *output = calloc(1, 1); //just in case
    while (!feof(fp)) {
        *output = realloc(*output, length + smart_size + sizeof(wchar_t));
        count = fread(*output + length, 1, smart_size, fp);
        memset(*output + length + count, 0, sizeof(wchar_t)); // append 0, in case of wide char
        length += count;
    }
    *output = realloc(*output, length + sizeof(wchar_t));
    //
    return length;
}


//int _tmain(int argc, _TCHAR** argv)
int main(int argc, char** argv)
{
    HMODULE hModJSP;
    FARPROC pIIAPDEx;
    FARPROC pIGPIEx;
    FARPROC pIIDAPDEx;
    //
    CScriptSite *pCScriptSite;
    IActiveScriptSiteVtbl   IActiveScriptSiteVtbl_hack;
    HRESULT hr;
    char MBCP[8];
    //
    char    *pacpath, *url, *host, *proxy, *lpAutoProxyScriptBuffer;
    wchar_t *url_w, *host_w, *proxy_w, *lpAutoProxyScriptBuffer_w;
    BSTR bScript = NULL;
    VARIANT varScript;
    FILE *fp;
    size_t len;
    char  pFilename[MAX_PATH + 1], *ProductVersion;
    int *aProductVersion = NULL; // 4 elems in array
    int CP, ret;
    //
    if (argc != 3) {
        fprintf(stderr, "PAC file debugger. v0.1.0 @lifenjoiner #20171002\n");
        fprintf(stderr, "This program insists the same capability as the windows OS, and printing the position where error ocured!\n");
        fprintf(stderr, "Usage: %s <pac-file> <url>\n", argv[0]);
        fprintf(stderr, "Tips: When the script has dead loops, you'd better use IE's DevTools. And that's why this program is named dbger.\n");
        return 1;
    }
    //
    CP = _getmbcp();
    sprintf(MBCP, ".%d", CP);
    setlocale(LC_CTYPE, MBCP);
    //
    ret = 0;
    pacpath = argv[1];
    url = argv[2];
    if (cs_to_utf16(CP, url, &url_w) <= 0) {
        fprintf(stderr, "Can't convert url to UTF-16!\n");
        goto ERR;
    }
    host = gethost(url);
    if (!host) {
        fprintf(stderr, "Can't get host from url!\n");
        goto ERR;
    }
    if (cs_to_utf16(CP, host, &host_w) <= 0) {
        fprintf(stderr, "Can't convert host to UTF-16!\n");
        goto ERR;
    }
    fp = fopen(pacpath, "rb");
    if (!fp) {
        fprintf(stderr, "Can't open file: %s\n", pacpath);
        goto ERR;
    }
    len = read_file(fp, &lpAutoProxyScriptBuffer);
    fclose(fp);
    if (!len) {
        fprintf(stderr, "Empty file: %s\n", pacpath);
        goto ERR;
    }
    // Extra: wchar_t needed for jscript!
    if (cs_to_utf16(CP, lpAutoProxyScriptBuffer, &lpAutoProxyScriptBuffer_w) <= 0) {
        fprintf(stderr, "Can't convert AutoProxyScriptBuffer to UTF-16!\n");
        goto ERR;
    }
    //
    hModJSP = LoadLibrary( TEXT("jsproxy") );
    if (!hModJSP) {
        fprintf(stderr, "LoadLibrary failed to load jsproxy.dll with error: %d\n", GetLastError());
        goto ERR;
    }
    //
    if (GetModuleFileName(hModJSP, pFilename, MAX_PATH) == 0) {
        fprintf(stderr, "GetModuleFileName failed for jsproxy.dll with error: %d\n", GetLastError());
        goto ERR;
    }
    ProductVersion = GetFileVersionStr(pFilename);
    if ( GetVersionArray(ProductVersion, &aProductVersion) != 4 ) {
        fprintf(stderr, "Can't get ProductVersion of jsproxy.dll in 4 parts.\n");
        goto ERR;
    }
    if (aProductVersion[0] < 8 || (aProductVersion[0] == 8 && aProductVersion[2] <= 6001 && aProductVersion[3] <= 18702)) {
        fprintf(stderr, "jsproxy.dll <= v8.0.6001.18702 is NOT supported!\n");
        goto ERR;
    }
    //
    pIIAPDEx     = GetProcAddress_FBK(hModJSP, "InternetInitializeAutoProxyDllEx");
    if (!pIIAPDEx) {goto ERR;}
    pIGPIEx     = GetProcAddress_FBK(hModJSP, "InternetGetProxyInfoEx");
    if (!pIGPIEx) {goto ERR;}
    pIIDAPDEx     = GetProcAddress_FBK(hModJSP, "InternetDeInitializeAutoProxyDllEx");
    if (!pIIDAPDEx) {goto ERR;}
    //
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (hr != S_OK) {
        fprintf(stderr, "CoInitializeEx failed: %d\n", hr);
        goto ERR;
    }
    //
    // Can we hack 'OnScriptError' before initializing? ...
    // Actually, we initialize the ScriptSite with a dummy script, hack, and then parse the script to get the errors ^_^
    bScript = SysAllocString(L"function FindProxyForURL(url,host){}"); // total time, faster
    varScript.bstrVal = bScript;
    varScript.wReserved1 = 0; // It will compare DWORD.
    *((DWORD*)&(varScript.wReserved2)) = (DWORD)bScript; // let's overwrite
    // For all supported versions
    if (aProductVersion[0] >= 10) {
        varScript.vt = 8;
        ret = pIIAPDEx(0, 0, NULL, &varScript, &pCScriptSite, NULL);
        if (ret) {
            fprintf(stderr, "InternetInitializeAutoProxyDllEx failed: %d\n", ret);
            goto ERR;
        }
        if ( InternetGetProxyInfoEx_X_dbg(pCScriptSite, lpAutoProxyScriptBuffer_w, pIGPIEx, url_w, 0, host_w, 0, &proxy_w, NULL) ) {
            goto ERR;
        }
        //
        wprintf(L"%s\n", proxy_w);
        GlobalFree(proxy_w);
    } else {
        varScript.vt = 12;
        ret = pIIAPDEx(0, 0, NULL, &varScript, &pCScriptSite, NULL);
        if (ret) {
            fprintf(stderr, "InternetInitializeAutoProxyDllEx failed: %d\n", ret);
            goto ERR;
        }
        // branch
        if (aProductVersion[0] == 9) {
            ret = InternetGetProxyInfoEx_X_dbg(pCScriptSite, lpAutoProxyScriptBuffer_w, pIGPIEx, url, 0, host, 0, &proxy, NULL);
        } else {
            int proxy_len;
            ret = InternetGetProxyInfoEx_X_dbg(pCScriptSite, lpAutoProxyScriptBuffer_w, pIGPIEx, url, strlen(url), host, strlen(host), &proxy, &proxy_len);
        }
        if (ret) { goto ERR; }
        //
        printf("%s\n", proxy);
        GlobalFree(proxy);
    }
    //
GOT:
    pIIDAPDEx(&pCScriptSite);
    CoUninitialize();
    //
CLEAN:
    // pacpath and url don't need free
    free(url_w);
    free(host);
    free(host_w);
    if (bScript) SysFreeString(bScript);
    free(lpAutoProxyScriptBuffer);
    free(lpAutoProxyScriptBuffer_w);
    FreeLibrary(hModJSP);
    //
    return ret;
    //
ERR:
    ret = 1;
    goto CLEAN;
}