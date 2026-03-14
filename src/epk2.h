#include <CPP/Windows/PropVariant.h>
#include <windows.h>

namespace Epk2 {
    
    struct CItem {
        AString name;
        UInt32 offset;
        UInt32 size;
        AString platformID;
        UInt32 segmentCount;
    };

    NWindows::NCOM::CPropVariant GetProperty(PROPID propId);

    // --

    #define SIGNATURE_SIZE 128

    static const Byte epak_Magic[] = {'e', 'p', 'a', 'k'};
    static const Byte epk2_Magic[] = {'E', 'P', 'K', '2'};

    #pragma pack(push, 1)
    struct Header {
        Byte    epakMagicBytes[4];
        UInt32  dataSize;
        UInt32  pakCount;
        Byte    epk2MagicBytes[4];
        uint8_t version[4];
        char    otaID[32];

    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct PakEntry {
        UInt32 offset;
        UInt32 size;
        char   name[4];
        char   unknown[4];
        UInt32 segmentSize;
    };
    #pragma pack(pop)

    static const Byte pakMagic[] = {'M', 'P', 'A', 'K'};

    #pragma pack(push, 1)
    struct PakHeader {
        char    pakName[4];
        UInt32  imageSize;
        char    platformID[64];
        UInt32  swVersion;
        UInt32  swDate;
        UInt32  buildType;
        UInt32  segmentCount;
        UInt32  segmentSize;
        UInt32  segmentIndex;
        char    pakMagic[4];
        char    reserved[24];
        UInt32  segmentChecksum;
    };
    #pragma pack(pop)

}