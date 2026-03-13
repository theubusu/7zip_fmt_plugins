#include "epk1.h"
#include "util.h"

#include <C/CpuArch.h>

#include <CPP/Common/ComTry.h>
#include <CPP/Common/MyBuffer.h>
#include <CPP/Common/MyCom.h>
#include <CPP/Common/UTFConvert.h>

#include <CPP/7zip/Archive/IArchive.h>
#include <CPP/7zip/Common/LimitedStreams.h>
#include <CPP/7zip/Common/ProgressUtils.h>
#include <CPP/7zip/Common/RegisterArc.h>
#include <CPP/7zip/Common/StreamObjects.h>
#include <CPP/7zip/Common/StreamUtils.h>

#include <CPP/7zip/Compress/CopyCoder.h>
#include <vector>
#include <string>

namespace Epk1 {
    
    Z7_CLASS_IMP_CHandler_IInArchive_2(IInArchiveGetStream, IOutArchive)
        CMyComPtr<IInStream> _inStream;
        CObjectVector<CItem> _items;
        UInt64 _headerSize;
        char _version[4];
        std::string _otaID;

        HRESULT Open2(IInStream* stream);
    };

    // specifies the avaliable properties of the archive itself
    static const Byte kArcProps[] = {
        kpidHeadersSize,
        kpidComment,        //used for OTAID + ver
    };
    IMP_IInArchive_ArcProps;

    // specifies the avaliable property of the files contained within the archive
    static const Byte kProps[] = {
        kpidPath,
        kpidIsDir,
        kpidSize,
        kpidPackSize,
        kpidOffset,
        kpidComment,        // used for version in PAK header
    };
    IMP_IInArchive_Props;

    // helper used in GetProperty
    static void Utf8StringToProp(const AString& s, NWindows::NCOM::CPropVariant& prop) {
        if (!s.IsEmpty()) {
            UString us;
            ConvertUTF8ToUnicode(s, us);
            prop = us;
        }
    }

    Z7_COM7F_IMF(CHandler::Open(IInStream* stream, const UInt64* /* maxCheckStartPosition */, IArchiveOpenCallback* /* openArchiveCallback */)) {
        DBG_LOG("[epk1] Open\n");

        COM_TRY_BEGIN
        {
            Close();
            if (Open2(stream) != S_OK) {
                DBG_LOG("[epk1] Open2 fail\n");
                return S_FALSE;
            }
            DBG_LOG("[epk1] Open2 ok\n");
            _inStream = stream;
        }
        return S_OK;
        COM_TRY_END
    }

    HRESULT CHandler::Open2(IInStream* stream) {
        
        // read common header
        Byte buf[16];
        RINOK(ReadStream_FALSE(stream, buf, 16));

        CommonHeader header;
        memcpy(&header, buf, sizeof(header));

        if (memcmp(header.MagicBytes, k_Signature, 4) != 0) {
            DBG_LOG("[epk1] fail signature\n");
            return S_FALSE;
        }

        DBG_LOG("[epk1] dataSize %i\n", header.DataSize);
        DBG_LOG("[epk1] pakCount %u\n", header.PakCount);

        //the offset of first entry which appears after common header used as header size
        _headerSize = GetUi32(buf + sizeof(CommonHeader));
        DBG_LOG("[epk1] headerSize %llu\n", _headerSize);

        //max pak count will be headersize - 12(common header) - 32(ota id) - 4(version u32) / 8(size of each pak entry)
        UInt32 maxPakCount = (_headerSize - sizeof(CommonHeader) - OTA_ID_SIZE - 4) / sizeof(PakEntry);
        DBG_LOG("[epk1] maxPakCount %i\n", maxPakCount);

        //read the paks buf based on max pak count
        RINOK(InStream_SeekSet(stream, sizeof(CommonHeader)));
        size_t pakEntriesSize = maxPakCount * sizeof(PakEntry);
        std::vector<Byte> pakEntriesBuf(pakEntriesSize);
        RINOK(ReadStream_FALSE(stream, pakEntriesBuf.data(), pakEntriesSize));

        _items.Clear();

        for (UInt32 i = 0; i < maxPakCount; i++) {
            //todo use structs here
            UInt32 offset = GetUi32(pakEntriesBuf.data() + i * 8);
            UInt32 size = GetUi32(pakEntriesBuf.data() + i * 8 + 4);

            if (offset == 0 && size == 0) {
                continue;
            }

            //read pak header to get pak's name
            const size_t kPakHdrSize = 128;
            Byte pakHdr[kPakHdrSize];
            RINOK(InStream_SeekSet(stream, offset));
            RINOK(ReadStream_FALSE(stream, pakHdr, kPakHdrSize));

            char name[8];
            memcpy(name, pakHdr, 4);
            name[4] = '\0';

            AString entryName(name);
            entryName += ".pak";

            //pak platform id/versionidk
            const size_t pakVersionSize = 64;
            char pakVersionB[pakVersionSize];
            memcpy(pakVersionB, pakHdr + 8, pakVersionSize);
            AString pakVersion(pakVersionB);

            CItem item;
            item.Name = entryName;
            item.Offset = offset + (UInt32)kPakHdrSize;
            item.Size = size - kPakHdrSize;
            item.Version = pakVersion;
            _items.Add(item);
            DBG_LOG("[epk1] create item %i - name %s, offset %i, size %i, version %s\n", i, name, item.Offset, item.Size, pakVersionB);
        }

        RINOK(InStream_SeekSet(stream, sizeof(CommonHeader) + pakEntriesSize));

        // read version
        char verBuf[4];
        RINOK(ReadStream_FALSE(stream, verBuf, 4));
        DBG_LOG("[epk1] ver %02x.%02x.%02x\n", verBuf[2], verBuf[1], verBuf[0]);
        memcpy(_version, verBuf, sizeof(_version));

        // read otaid
        char otaIDBuf[OTA_ID_SIZE];
        RINOK(ReadStream_FALSE(stream, otaIDBuf, OTA_ID_SIZE));
        std::string otaID = otaIDBuf;
        DBG_LOG("[epk1] otaID %s\n", otaID.c_str());
        _otaID = otaID;

        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::Close()) {
        DBG_LOG("[epk1] Close\n");

        _inStream.Release();
        _items.Clear();
        _headerSize = 0;
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback)) {
        DBG_LOG("[epk1] Extract\n");

        COM_TRY_BEGIN
        const bool allFilesMode = (numItems == (UInt32) (Int32) -1);
        if (allFilesMode) {
            numItems = _items.Size();
        }

        if (numItems == 0) {
            return S_OK;
        }

        UInt64 totalSize = 0;
        UInt32 i;
        for (i = 0; i < numItems; i++) {
            const CItem& item = _items[allFilesMode ? i : indices[i]];
            totalSize += item.Size;
        }
        DBG_LOG("[epk1] total size: %llu\n", totalSize);
        extractCallback->SetTotal(totalSize);

        UInt64 currentTotalSize = 0;

        NCompress::CCopyCoder* copyCoderSpec = new NCompress::CCopyCoder();
        CMyComPtr<ICompressCoder> copyCoder = copyCoderSpec;

        CLocalProgress* lps = new CLocalProgress;
        CMyComPtr<ICompressProgressInfo> progress = lps;
        lps->Init(extractCallback, false);

        CLimitedSequentialInStream* streamSpec = new CLimitedSequentialInStream;
        CMyComPtr<ISequentialInStream> fileStream(streamSpec);
        streamSpec->SetStream(_inStream);

        for (i = 0; i < numItems; i++) {
            lps->InSize = lps->OutSize = currentTotalSize;
            RINOK(lps->SetCur())
            CMyComPtr<ISequentialOutStream> realOutStream;
            const Int32 askMode = testMode ? NArchive::NExtract::NAskMode::kTest
                                        : NArchive::NExtract::NAskMode::kExtract;
            const UInt32 index = allFilesMode ? i : indices[i];
            const CItem& item = _items[index];
            RINOK(extractCallback->GetStream(index, &realOutStream, askMode))
            currentTotalSize += item.Size;

            if (!testMode && !realOutStream) {
                continue;
            }
            RINOK(extractCallback->PrepareOperation(askMode))
            if (testMode) {
                RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK))
                continue;
            }
            bool isOk = true;

            RINOK(InStream_SeekSet(_inStream, item.Offset))
            streamSpec->Init(item.Size);

            RINOK(copyCoder->Code(fileStream, realOutStream, NULL, NULL, progress))
            isOk = (copyCoderSpec->TotalSize == item.Size);
            realOutStream.Release();
            
            RINOK(extractCallback->SetOperationResult(
                isOk ? NArchive::NExtract::NOperationResult::kOK
                    : NArchive::NExtract::NOperationResult::kDataError
            ))
        }

        return S_OK;
        COM_TRY_END
    }
    

    Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32* numItems)) {
        DBG_LOG("[epk1] GetNumberOfItems\n");

        *numItems = _items.Size();
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)) {
        DBG_LOG("[epk1] GetArchiveProperty (propID=%lu)\n", propID);

        COM_TRY_BEGIN
        NWindows::NCOM::CPropVariant prop;
        switch (propID) {
            case kpidHeadersSize:
                prop = _headerSize;
                break;
            case kpidExtension:
                prop = "epk";
                break;
            case kpidComment: {
                char commentBuf[64];
                sprintf(commentBuf, "%s %02x.%02x.%02x", _otaID.c_str(), _version[2], _version[1], _version[0]);
                AString comment(commentBuf);
                Utf8StringToProp(comment, prop);
                break;
            }
        }
        prop.Detach(value);
        return S_OK;
        COM_TRY_END
    }

    Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value)) {
        DBG_LOG("[epk1] GetProperty (index=%i, propID=%lu)\n", index, propID);

        COM_TRY_BEGIN
        NWindows::NCOM::CPropVariant prop;
        const CItem& item = _items[index];

        switch (propID) {
            case kpidPath:
                Utf8StringToProp(item.Name, prop);
                break;
            case kpidIsDir:
                prop = false;
                break;
            case kpidSize:
            case kpidPackSize:
                prop = item.Size;
                break;
            case kpidOffset:
                prop = item.Offset;
                break;
            case kpidComment:
                Utf8StringToProp(item.Version, prop);
                break;
        }

        prop.Detach(value);
        return S_OK;
        COM_TRY_END
    }
 
    Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream** stream)) {
        DBG_LOG("[epk1] GetStream\n");

        *stream = NULL;
        COM_TRY_BEGIN

        const CItem& item = _items[index];
        return CreateLimitedInStream(_inStream, item.Offset, item.Size, stream);

        COM_TRY_END
    }
    
    Z7_COM7F_IMF(CHandler::GetFileTimeType(UInt32* type)) {
        DBG_LOG("[epk1] GetFileTimeType\n");

        *type = k_PropVar_TimePrec_0;
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::UpdateItems(ISequentialOutStream* outStream, UInt32 numItems, IArchiveUpdateCallback* callback )) {
        DBG_LOG("[epk1] UpdateItems\n");

        COM_TRY_BEGIN
        return S_OK;
        COM_TRY_END
    }

    //register format
    REGISTER_ARC_I(
        "epk1",                 // format name
        "epk",                  // file extension
        NULL,                   // ?ae
        0xA3,                   // unique id for GUID
        k_Signature,            // file magic signature
        0,                      // offset of signature
        0,                      // arc flags
        0                       // isArc
    )
}