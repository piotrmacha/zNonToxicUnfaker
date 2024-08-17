#include <Union/Hook.h>
#include <Union/RawMemory.h>
#include <ZenGin/zGothicAPI.h>

struct Patch {
    uint32_t offset;
    uint8_t expected[2];
    uint8_t replacement[2];
};

// G2A: 0x00424C70 public: void __thiscall CGameManager::Init(struct HWND__ * &)
// G2:  0x00424940 public: void __thiscall CGameManager::Init(struct HWND__ * &)
// G1A: 0x00426B20 public: void __thiscall CGameManager::Init(struct HWND__ * &)
// G1:  0x004240C0 public: void __thiscall CGameManager::Init(struct HWND__ * &)
void __fastcall CGameManager_Init_PartialHook(Union::Registers &reg) {
    if (Union::Dll *othelloAbi = Union::Dll::Load("OTHELLO_ABI.DLL")) {
        void *imageBase;
        size_t imageLength;
        othelloAbi->GetRange(imageBase, imageLength);
        const auto rawMemory = Union::RawMemory::GetAccess(
                imageBase, reinterpret_cast<void *>(reinterpret_cast<uint32_t>(imageBase) + imageLength));

        Patch patches[] = {
                {0x100AE, {0x74, 0x09}, {0x90, 0x90}},
                {0x10096, {0x6A, 0x01}, {0xEB, 0x2B}}, // Kudos to fyryNy
                {0x1180d, {0x6A, 0xFF}, {0xEB, 0x06}}, // Kudos to fyryNy
        };

        for (const auto &[offset, expected, replacement]: patches) {
            const auto &data = rawMemory->Get<uint16_t>(offset);
            auto &data1 = rawMemory->Get<uint8_t>(offset);
            auto &data2 = rawMemory->Get<uint8_t>(offset + 1);
            (Union::String::MakeHexadecimal(imageBase) + "+" + Union::String::MakeHexadecimal(offset) + ": " +
             Union::String::MakeHexadecimal(data))
                    .StdPrintLine();
            if (data1 == expected[0] && data2 == expected[1]) {
                data1 = replacement[0];
                data2 = replacement[1];
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
    }
}
auto Ivk_CGameManager_Init_PartialHook = Union::CreatePartialHook(reinterpret_cast<void *>(zSwitch(0x004240C0, 0x00426B20, 0x00424940, 0x00424C70)), &CGameManager_Init_PartialHook);
