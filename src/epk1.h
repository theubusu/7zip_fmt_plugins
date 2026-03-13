#include <CPP/Windows/PropVariant.h>
#include <windows.h>

namespace Epk1 {
    
    struct CItem {
        AString name;
        UInt32 offset;
        UInt32 size;
        AString version;
    };

    NWindows::NCOM::CPropVariant GetProperty(PROPID propId);

    // --

    static const Byte k_Signature[] = {'e', 'p', 'a', 'k'};

    #pragma pack(push, 1)
    struct CommonHeader {
        Byte   magicBytes[4];
        UInt32 dataSize;
        UInt32 pakCount;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct PakEntry {
        UInt32 offset;
        UInt32 size;
    };
    #pragma pack(pop)

    #define OTA_ID_SIZE 0x20

}