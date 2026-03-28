// NonToxicUnfaker — Othello 4.3.5 plugin bypass
// Patches OTHELLO_ABI.DLL at runtime to allow arbitrary Union plugins to load.
// Two patches are applied via LdrRegisterDllNotification as soon as the DLL maps.
//
// Patch 1 (0x5FF8A): je → jmp — skips blocklist registration so our plugin
//   name is never added to the error string.
//
// Patch 2 (0x4BF79): FF D0 → 90 90 — NOPs the indirect call in the random
//   dispatcher (sub_1004BEF0) that selects and invokes a plugin-checker
//   routine. Because all checker variants are reached exclusively through
//   this single call site, one NOP permanently disables every checker
//   regardless of which variant the dispatcher would have chosen.

#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <cstdint>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

// ---- NTDLL undocumented structures required for LdrRegisterDllNotification ----

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG            Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID            DllBase;
    ULONG            SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG            Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID            DllBase;
    ULONG            SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA   Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG                       NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA  NotificationData,
    PVOID                       Context);

typedef NTSTATUS (NTAPI *pLdrRegisterDllNotification)(
    ULONG                          Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID                          Context,
    PVOID                         *Cookie);

// ---- Globals ----

static PVOID g_DllNotificationCookie = nullptr;
static char  g_LogPath[MAX_PATH]     = {0};

// ---- Logging ----

static void LogToFile(const char *format, ...) {
    if (g_LogPath[0] == '\0')
        return;
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    FILE *f;
    if (fopen_s(&f, g_LogPath, "a") == 0) {
        fprintf(f, "%s", buffer);
        fclose(f);
    }
}

// ---- Patch table ----

struct Patch {
    uint32_t offset;
    uint8_t  size;
    uint8_t  expected[6];
    uint8_t  replacement[6];
};

static const Patch k_OthelloPatches[] = {
    // Skip blocklist registration: je → jmp
    // Prevents our DLL name from being appended to the blocked-plugin string.
    { 0x5FF8A, 2, { 0x74, 0x09 }, { 0xEB, 0x09 } },

    // NOP the checker dispatcher: call eax (FF D0) → NOP NOP (90 90)
    // sub_1004BEF0 randomly selects one of several identical plugin-checking
    // routines and calls it through a function-pointer table. All paths lead
    // here; two NOPs disable all of them permanently.
    { 0x4BF79, 2, { 0xFF, 0xD0 }, { 0x90, 0x90 } },
};

// ---- Core patcher ----

static void ApplyPatches(const wchar_t *name, void *base, size_t size) {
    if (_wcsicmp(name, L"OTHELLO_ABI.DLL") != 0)
        return;

    LogToFile("[Unfaker] Patching OTHELLO_ABI.DLL at %p\n", base);

    for (const auto &p : k_OthelloPatches) {
        uint8_t *data = reinterpret_cast<uint8_t *>(
            reinterpret_cast<uintptr_t>(base) + p.offset);

        DWORD old;
        if (!VirtualProtect(data, p.size, PAGE_EXECUTE_READWRITE, &old)) {
            LogToFile("  -> @%08X: VirtualProtect failed\n", p.offset);
            continue;
        }

        if (memcmp(data, p.expected, p.size) == 0) {
            memcpy(data, p.replacement, p.size);
            LogToFile("  -> @%08X: OK\n", p.offset);
        } else {
            LogToFile("  -> @%08X: MISS (found %02X %02X, expected %02X %02X)\n",
                p.offset, data[0], data[1], p.expected[0], p.expected[1]);
        }

        VirtualProtect(data, p.size, old, &old);
    }
}

// ---- DLL notification callback ----

static VOID CALLBACK DllNotificationCallback(
    ULONG                      Reason,
    PLDR_DLL_NOTIFICATION_DATA Data,
    PVOID                      Context)
{
    // Reason 1 = LDR_DLL_NOTIFICATION_REASON_LOADED
    if (Reason == 1 && Data && Data->Loaded.BaseDllName)
        ApplyPatches(Data->Loaded.BaseDllName->Buffer,
                     Data->Loaded.DllBase,
                     Data->Loaded.SizeOfImage);
}

// ---- Initialization ----

static void Initialize() {
    // Case A: OTHELLO_ABI.DLL is already in memory when we load.
    HMODULE hMod = GetModuleHandleW(L"OTHELLO_ABI.DLL");
    if (hMod) {
        MODULEINFO mi;
        if (GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
            ApplyPatches(L"OTHELLO_ABI.DLL", mi.lpBaseOfDll, mi.SizeOfImage);
    }

    // Case B: Register a callback for when it loads later.
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        auto RegFn = reinterpret_cast<pLdrRegisterDllNotification>(
            GetProcAddress(hNtDll, "LdrRegisterDllNotification"));
        if (RegFn)
            RegFn(0, DllNotificationCallback, nullptr, &g_DllNotificationCookie);
    }
}

// ---- DLL entry point ----

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Set up log file next to our DLL.
        if (GetModuleFileNameA(hModule, g_LogPath, MAX_PATH)) {
            char *last = strrchr(g_LogPath, '\\');
            if (last) *last = '\0';
            strncat(g_LogPath, "\\unfaker.txt",
                    MAX_PATH - strlen(g_LogPath) - 1);
            FILE *f;
            if (fopen_s(&f, g_LogPath, "w") == 0) {
                fprintf(f, "[Unfaker] Started.\n");
                fclose(f);
            }
        }

        Initialize();
    }
    return TRUE;
}
