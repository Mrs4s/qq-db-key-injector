#include "windows.h"
#include "detours.h"
#include "sqlite3.h"

#include <fstream>


DWORD SigScan(const char *szPattern, int offset = 0);

void InitializeSigScan(DWORD ProcessID, const char *Module);

void FinalizeSigScan();

#pragma comment(lib, "lib\\SigScan.lib")
 

static PVOID originalFuncAddress = 0;
static PVOID sqlite3DbFilenameAddress = 0;

char *to_hex_string(const unsigned char *array, size_t length) {
    char *outstr = static_cast<char *>(malloc(2 * length + 1));
    if (!outstr) return outstr;
    char *p = outstr;
    for (size_t i = 0; i < length; ++i) {
        p += sprintf(p, "%02hhx", array[i]);
    }
    return outstr;
}


int hookedSqlite3Key(sqlite3 *_this, const void *key, int size) {
    byte *buff = static_cast<byte *>(malloc(size));
    memcpy(buff, key, size);
    auto ret = ((int (*)(sqlite3 *, const void *, int)) (originalFuncAddress))(_this, key, size);
    auto name = ((const char *(*)(sqlite3 *, const char *)) (sqlite3DbFilenameAddress))(_this, "main");
    std::ofstream writer("db_key_log.txt", std::ios::app);
    writer << name << ":" << std::endl;
    writer << to_hex_string(buff, size) << std::endl;
    writer << std::endl;
    writer.close();
    return ret;
}


void installHook() {
    InitializeSigScan(GetCurrentProcessId(), "KernelUtil.dll");
    originalFuncAddress = (PVOID) SigScan("##558BEC566B751011837D1010740D6817020000E8");
    sqlite3DbFilenameAddress = (PVOID) SigScan("##558BECFF750CFF7508E8B8D10200595985");

    if (!originalFuncAddress) {
        MessageBoxA(NULL, "sqlite3_key func not found", "Hook", MB_OK);
        return;
    }

    FinalizeSigScan();
    DetourAttach(&(PVOID &) originalFuncAddress, (PVOID) hookedSqlite3Key);
}


BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            installHook();
            DetourTransactionCommit();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

