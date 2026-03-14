#include "epk3.h"
#include "util.h"
#include "epkKeys.h"

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


namespace Epk3 {
    
    Z7_CLASS_IMP_CHandler_IInArchive_2(IInArchiveGetStream, IOutArchive)
        CMyComPtr<IInStream> _inStream;
        CObjectVector<CItem> _items;
        UInt64 _headerSize;
        uint8_t _version[4];
        std::string _otaID;
        uint8_t _key[16];

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
        kpidNumSubFiles,        //use for segmrnt count
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
        DBG_LOG("[epk3] Open\n");

        COM_TRY_BEGIN
        {
            Close();
            if (Open2(stream) != S_OK) {
                DBG_LOG("[epk3] Open2 fail\n");
                return S_FALSE;
            }
            DBG_LOG("[epk3] Open2 ok\n");
            _inStream = stream;
        }
        return S_OK;
        COM_TRY_END
    }

    HRESULT CHandler::Open2(IInStream* stream) {
        //skip header signature
        RINOK(InStream_SeekSet(stream, SIGNATURE_SIZE));

        // read header
        const size_t headerReadSize = 1584; //max header size
        Byte hdrBuf[headerReadSize];
        RINOK(ReadStream_FALSE(stream, hdrBuf, headerReadSize));

        Header header;

        //try to find key 
        const uint8_t* key = tryFindAESkey(hdrBuf, headerReadSize, epk3_Magic, sizeof(epk3_Magic), 0);
        if (key) {
            DBG_LOG("[epk3] matched key: ");
            for (int i = 0; i < 16; i++) {
                DBG_LOG("%02X ", key[i]);
            }    
            DBG_LOG("\n");
            memcpy(_key, key, 16);

            //decrypt header
            decryptAES128ecbUnalign(hdrBuf, headerReadSize, _key);
            memcpy(&header, hdrBuf, sizeof(header));

        } else {
            //no key, return false
            DBG_LOG("[epk3] not found key...\n");
            return S_FALSE;
        } 

        DBG_LOG("[epk3] version %02x.%02x.%02x.%02x\n", header.version[3], header.version[2], header.version[1], header.version[0]);
        memcpy(_version, header.version, sizeof(_version));
        std::string otaID = header.otaID;

        DBG_LOG("[epk3] otaID %s\n", otaID.c_str());
        _otaID = otaID;

        DBG_LOG("[epk3] packageInfoSize %i\n", header.packageInfoSize);

        _items.Clear();

        //read and decrypt pkginfo
        RINOK(InStream_SeekSet(stream, SIGNATURE_SIZE+headerReadSize+36+SIGNATURE_SIZE));
        std::vector<Byte> pkgInfo(header.packageInfoSize);
        RINOK(ReadStream_FALSE(stream, pkgInfo.data(), header.packageInfoSize));
        decryptAES128ecbUnalign(pkgInfo.data(), header.packageInfoSize, _key);

        PkgInfoHeader pkgInfoHeader;
        memcpy(&pkgInfoHeader, pkgInfo.data(), sizeof(pkgInfoHeader));
        DBG_LOG("[epk3] pkgInfo listSize %i\n", pkgInfoHeader.packageInfoListSize);
        DBG_LOG("[epk3] pkgInfo count %i\n", pkgInfoHeader.packageInfoCount);

        int entryIdx = 0;
        int pakIdx = 0;
        int offset = SIGNATURE_SIZE+headerReadSize+36+SIGNATURE_SIZE+header.packageInfoSize;
        while (entryIdx < pkgInfoHeader.packageInfoCount) {
            PkgInfoEntry entry;
            memcpy(&entry, pkgInfo.data() + sizeof(PkgInfoHeader) + (entryIdx*sizeof(PkgInfoEntry)), sizeof(entry));

            char name[132];
            memcpy(name, entry.packageName, 128);

            AString entryName(name);
            entryName += ".pak";

            CItem item;
            item.name = entryName;
            item.offset = offset;
            item.size = entry.packageSize;
            item.segmentCount = entry.segmentCount;
            item.segmentSize = entry.segmentSize;
            _items.Add(item);
            DBG_LOG("[epk3] create item %i - name: %s, offset: %i, size: %i, segcount: %i, segsize: %i\n", pakIdx, name, item.offset, item.size, item.segmentCount, item.segmentSize);
            pakIdx++;

            for (UInt32 segIdx = 0; segIdx < entry.segmentCount; segIdx++) {
                if (segIdx > 0) {
                    memcpy(&entry, pkgInfo.data() + sizeof(PkgInfoHeader) + (entryIdx*sizeof(PkgInfoEntry)), sizeof(entry));
                }
                DBG_LOG("[epk3] seg %i/%i, size: %i\n", entry.segmentIndex, entry.segmentCount, entry.segmentSize);
                offset += SIGNATURE_SIZE + entry.segmentSize;

                entryIdx++;
            }
        }

        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::Close()) {
        DBG_LOG("[epk3] Close\n");

        _inStream.Release();
        _items.Clear();
        _headerSize = 0;
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback)) {
        DBG_LOG("[epk3] Extract\n");

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
            totalSize += item.size;
        }
        DBG_LOG("[epk3] total size: %llu\n", totalSize);
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
            //processed count
            lps->InSize = lps->OutSize = currentTotalSize;
            RINOK(lps->SetCur())

            CMyComPtr<ISequentialOutStream> realOutStream;
            const Int32 askMode = testMode ? NArchive::NExtract::NAskMode::kTest
                                        : NArchive::NExtract::NAskMode::kExtract;
            const UInt32 index = allFilesMode ? i : indices[i];
            const CItem& item = _items[index];
            RINOK(extractCallback->GetStream(index, &realOutStream, askMode))
            //currentTotalSize += item.size;

            //  !!    TODO FIX THIS TESTING
            if (!testMode && !realOutStream) {
                continue;
            }
            RINOK(extractCallback->PrepareOperation(askMode))
            if (testMode) {
                RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK))
                continue;
            }
            bool isOk = true;
            UInt64 itemWritten = 0;

            ///
            RINOK(InStream_SeekSet(_inStream, item.offset));

            for (UInt32 seg = 0; seg < item.segmentCount; seg++) {
                UInt64 itemRemain = item.size - itemWritten;
                //DBG_LOG("[epk3] remain %llu\n", itemRemain);

                size_t readSize;
                if (itemRemain < item.segmentSize) {
                    readSize = itemRemain;
                } else {
                    readSize = item.segmentSize;
                }

                Byte pakSignature[SIGNATURE_SIZE];
                RINOK(ReadStream_FALSE(_inStream, pakSignature, SIGNATURE_SIZE));

                std::vector<Byte> segmentData(readSize);
                RINOK(ReadStream_FALSE(_inStream, segmentData.data(), readSize));
                //decrypt data
                decryptAES128ecbUnalign(segmentData.data(), readSize, _key);

                //write decrypted segment to output stream
                UInt32 written;
                RINOK(realOutStream->Write(segmentData.data(), segmentData.size(), &written));
                if (written != segmentData.size()) {
                    DBG_LOG("[epk3] fail pak written size\n");
                    isOk = false;
                }

                //update progress
                itemWritten += written;
                lps->InSize = lps->OutSize = currentTotalSize + itemWritten;
                RINOK(lps->SetCur());
            }

            currentTotalSize += item.size;  // now add the full item size after processing

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
        DBG_LOG("[epk3] GetNumberOfItems\n");

        *numItems = _items.Size();
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)) {
        DBG_LOG("[epk3] GetArchiveProperty (propID=%lu)\n", propID);

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
                sprintf(commentBuf, "%s %02x.%02x.%02x.%02x", _otaID.c_str(), _version[3], _version[2], _version[1], _version[0]);
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
        DBG_LOG("[epk3] GetProperty (index=%i, propID=%lu)\n", index, propID);

        COM_TRY_BEGIN
        NWindows::NCOM::CPropVariant prop;
        const CItem& item = _items[index];

        switch (propID) {
            case kpidPath:
                Utf8StringToProp(item.name, prop);
                break;
            case kpidIsDir:
                prop = false;
                break;
            case kpidSize:
            case kpidPackSize:
                prop = item.size;
                break;
            case kpidOffset:
                prop = item.offset;
                break;
            case kpidNumSubFiles:
                prop = item.segmentCount;
                break;
        }

        prop.Detach(value);
        return S_OK;
        COM_TRY_END
    }
 
    //  !!    TODO IMPLEMENT TS SO OPEN INSIDE WORKS
    Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream** stream)) {
        DBG_LOG("[epk3] GetStream\n");

        *stream = NULL;
        COM_TRY_BEGIN

        const CItem& item = _items[index];
        return CreateLimitedInStream(_inStream, item.offset, item.size, stream);

        COM_TRY_END
    }
    
    Z7_COM7F_IMF(CHandler::GetFileTimeType(UInt32* type)) {
        DBG_LOG("[epk3] GetFileTimeType\n");

        *type = k_PropVar_TimePrec_0;
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::UpdateItems(ISequentialOutStream* outStream, UInt32 numItems, IArchiveUpdateCallback* callback )) {
        DBG_LOG("[epk3] UpdateItems\n");

        COM_TRY_BEGIN
        return S_OK;
        COM_TRY_END
    }

    //no signature register because of crypted header cannot check signature before decryption logic
    REGISTER_ARC_I_NO_SIG(
        "epk3", // format name
        "epk",  // file extension
        NULL,   // ?ae
        0xA3,   // unique id for GUID
        0,  //offset of signature ? even thogh it shouldnt be used here..
        0,  // arc flags
        0   // isArc
    )

    //register format
    //REGISTER_ARC_I(
    //    "epk3",                 // format name
    //    "epk",                  // file extension
    //    NULL,                   // ?ae
    //    0xA2,                   // unique id for GUID
    //    epk3_Magic,            // file magic signature
    //    140,                      // offset of signature
    //    0,                      // arc flags
    //    0                       // isArc
    //)
}