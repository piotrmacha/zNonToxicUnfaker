#include <Union/Hook.h>
#include <ZenGin/zGothicAPI.h>

struct Patch {
    uint32_t offset;
    uint8_t expected[2];
    uint8_t replacement[2];
};

void ExecuteUnfaker() {
    if (const Union::Dll *othelloAbi = Union::Dll::Load("OTHELLO_ABI.DLL")) {
        void *imageBase;
        size_t imageLength;
        DWORD oldProtection;
        othelloAbi->GetRange(imageBase, imageLength);

        Patch patches[] = {
                {0x100AE, {0x74, 0x09}, {0x90, 0x90}},
                {0x10096, {0x6A, 0x01}, {0xEB, 0x2B}}, // Kudos to fyryNy
                {0x1180d, {0x6A, 0xFF}, {0xEB, 0x06}}, // Kudos to fyryNy
        };

        VirtualProtect(imageBase, imageLength, PAGE_EXECUTE_READWRITE, &oldProtection);
        for (const auto &[offset, expected, replacement]: patches) {
            void* memory = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(imageBase) + offset);
            uint8_t* data = reinterpret_cast<uint8_t*>(memory);

            (Union::String::MakeHexadecimal(imageBase) + "+" + Union::String::MakeHexadecimal(offset) + ": " +
             Union::String::MakeHexadecimal(data))
                    .StdPrintLine();

            if (data[0] == expected[0] && data[1] == expected[1]) {
                *(data) = replacement[0];
                *(data + 1) = replacement[1];

                (Union::String("Patch applied at ") + Union::String::MakeHexadecimal(imageBase) + "+" +
                 Union::String::MakeHexadecimal(offset) + ": " + Union::String::MakeHexadecimal(replacement[0]) + " " +
                 Union::String::MakeHexadecimal(replacement[1]))
                        .StdPrintLine();

            } else {
                (Union::String("Patch NOT applied at ") + Union::String::MakeHexadecimal(imageBase) + "+" +
                 Union::String::MakeHexadecimal(offset) + ": " + Union::String::MakeHexadecimal(data) + " (expected: " +
                 Union::String::MakeHexadecimal(expected[0]) + " " + Union::String::MakeHexadecimal(expected[1]) + ")")
                        .StdPrintLine();
            }
        }
        VirtualProtect(imageBase, imageLength, oldProtection, nullptr);
    }
}

// G2A: 0x00424C70 public: void __thiscall CGameManager::Init(struct HWND__ * &)
// G2:  0x00424940 public: void __thiscall CGameManager::Init(struct HWND__ * &)
// G1A: 0x00426B20 public: void __thiscall CGameManager::Init(struct HWND__ * &)
// G1:  0x004240C0 public: void __thiscall CGameManager::Init(struct HWND__ * &)
auto Ivk_CGameManager_Init_Hook = Union::CreateHook(reinterpret_cast<void *>(0x004240C0), &Gothic_I_Classic::CGameManager::Init_Hooked);
void Gothic_I_Classic::CGameManager::Init_Hooked(HWND__*& hwnd) {
    ExecuteUnfaker();
    (this->*Ivk_CGameManager_Init_Hook)(hwnd);
}