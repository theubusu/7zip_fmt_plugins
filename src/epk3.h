#include <CPP/Windows/PropVariant.h>
#include <windows.h>

namespace Epk3 {
    
    struct CItem {
        AString name;
        UInt32 offset;
        UInt32 size;
        UInt32 segmentCount;
        UInt32 segmentSize;
    };

    NWindows::NCOM::CPropVariant GetProperty(PROPID propId);

    //custom archive properties
    enum {
        cIsNewType = 200,
        cplatformVersion,
        cSdkVersion,

        //for new header ext
        cencryptType,
        cupdateType,
        cupdatePlatformVersion,
        ccompatibleMinimumVersion,
        cneedToCheckCompatibleVersion,
    };

    // --

    #define MAX_HDR_SIZE 1712

    static const Byte epk3_Magic[] = {'E', 'P', 'K', '3'};

    #pragma pack(push, 1)
    struct Header {
        Byte    epk3MagicBytes[4];
        uint8_t version[4];
        char    otaID[32];
        UInt32  packageInfoSize;
        UInt32  bChunked;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct HeaderNewEx {
        char   pakInfoMagic[4];
        char   encryptType[6];
        char   updateType[6];
        float  updatePlatformVersion;
        float  compatibleMinimumVersion;
        int    needToCheckCompatibleVersion;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct PlatformVersions {
        UInt32 pad;
        char   platformVersion[16];
        char   sdkVersion[16];
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct PkgInfoHeader {
        UInt32 packageInfoListSize;
        UInt32 packageInfoCount;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct PkgInfoEntry {
        UInt32 packageType;
        UInt32 packageInfoSize;
        char   packageName[128];
        char   packageVersion[96];
        char   packageArchitecture[32];
        char   checksum[32];
        UInt32 packageSize;
        UInt32 dipk;
        UInt32 isSegmented;
        UInt32 segmentIndex;
        UInt32 segmentCount;
        UInt32 segmentSize;
        UInt32 unknown;
    };
    #pragma pack(pop)

}