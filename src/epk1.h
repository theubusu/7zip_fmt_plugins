#include <CPP/Windows/PropVariant.h>
#include <windows.h>

namespace Epk1 {
    
    struct CItem {
        AString Name;
        UInt32 Offset;
        UInt32 Size;
        AString Version;
    };

    NWindows::NCOM::CPropVariant GetProperty(PROPID propId);

    // --

    static const Byte k_Signature[] = {'e', 'p', 'a', 'k'};

    #pragma pack(push, 1)
    struct CommonHeader {
        Byte   MagicBytes[4];
        UInt32 DataSize;
        UInt32 PakCount;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct PakEntry {
        UInt32 Offset;
        UInt32 Size;
    };
    #pragma pack(pop)

    #define OTA_ID_SIZE 0x20

}