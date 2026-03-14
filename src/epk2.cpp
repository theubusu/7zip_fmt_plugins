#include "epk2.h"
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


namespace Epk2 {
    
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
        DBG_LOG("[epk2] Open\n");

        COM_TRY_BEGIN
        {
            Close();
            if (Open2(stream) != S_OK) {
                DBG_LOG("[epk2] Open2 fail\n");
                return S_FALSE;
            }
            DBG_LOG("[epk2] Open2 ok\n");
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

        bool isKeyFound = false;
        Header header;
        memcpy(&header, hdrBuf, sizeof(header));
        if (memcmp(header.epk2MagicBytes, epk2_Magic, 4) == 0) {
            DBG_LOG("[epk2] plain header signature\n");
        } else {
            //not found epk2 magic, the header could be encrypted so try to find key
            const uint8_t* key = tryFindAESkey(hdrBuf, headerReadSize, epk2_Magic, sizeof(epk2_Magic), 12);
            if (key) {
                DBG_LOG("[epk2] matched key: ");
                for (int i = 0; i < 16; i++) {
                    DBG_LOG("%02X ", key[i]);
                }    
                DBG_LOG("\n");
                isKeyFound = true;
                memcpy(_key, key, 16);

                //decrypt header
                decryptAES128ecbUnalign(hdrBuf, headerReadSize, _key);
                memcpy(&header, hdrBuf, sizeof(header));

            } else {
                //no key, return false
                DBG_LOG("[epk2] not found key...\n");
                return S_FALSE;
            } 
        }

        DBG_LOG("[epk2] dataSize %i\n", header.dataSize);
        DBG_LOG("[epk2] pakCount %u\n", header.pakCount);

        DBG_LOG("[epk2] version %02x.%02x.%02x.%02x\n", header.version[3], header.version[2], header.version[1], header.version[0]);
        memcpy(_version, header.version, sizeof(_version));
        std::string otaID = header.otaID;

        DBG_LOG("[epk2] otaID %s\n", otaID.c_str());
        _otaID = otaID;

        _items.Clear();

        UInt32 signatureCount = 1; //count header signature

        for (UInt32 i = 0; i < header.pakCount; i++) {
            PakEntry entry;
            memcpy(&entry, hdrBuf + sizeof(Header) + (i*sizeof(PakEntry)), sizeof(entry));

            char name[8];
            memcpy(name, entry.name, 4);
            name[4] = '\0';

            AString entryName(name);
            entryName += ".pak";

            //each segment starts with a signature that for some reason is not accounted for in the offset, so we need to precalculate actual offset and segment count here.
            UInt32 actualOffset = entry.offset + signatureCount*SIGNATURE_SIZE;
            UInt32 segmentCount = (entry.size + entry.segmentSize - 1) / entry.segmentSize;

            //DBG_LOG("[epk2] EARLY item %i - name %s, offset %i, size %i, segcount %i\n", i, name, actualOffset, entry.size, segmentCount);

            //each segment has one signature. so add segcount of sigs to running total.
            signatureCount += segmentCount;

            //jump to offset to read PAK header for pak version
            RINOK(InStream_SeekSet(stream, actualOffset + SIGNATURE_SIZE));
            Byte pakHdrB[sizeof(PakHeader)];
            RINOK(ReadStream_FALSE(stream, pakHdrB, sizeof(PakHeader)));

            //decrypt pak header
            //if key is not found at this point(because header was plain), we need to find the key using the Pak magic.
            if (!isKeyFound) {
                const uint8_t* key = tryFindAESkey(pakHdrB, sizeof(PakHeader), pakMagic, 4, 96);
                if (key) {
                    DBG_LOG("[epk2] matched key: ");
                    for (int i = 0; i < 16; i++) {
                        DBG_LOG("%02X ", key[i]);
                    }
                    DBG_LOG("\n");
                    memcpy(_key, key, 16);
                    isKeyFound = true;
                } else {
                    //no key, return false
                    DBG_LOG("[epk2] not found key...\n");
                    return S_FALSE;
                }
            }
            
            decryptAES128ecbUnalign(pakHdrB, sizeof(PakHeader), _key);
            PakHeader pakHdr;
            memcpy(&pakHdr, pakHdrB, sizeof(PakHeader));
            DBG_LOG("[epk2] pakHdr platid %s\n", pakHdr.platformID);
            AString platformID(pakHdr.platformID);

            CItem item;
            item.name = entryName;
            item.offset = actualOffset;
            item.size = entry.size;
            item.segmentCount = segmentCount;
            item.platformID = platformID;
            _items.Add(item);
            DBG_LOG("[epk2] create item %i - name %s, offset %i, size %i, segcount %i\n", i, name, item.offset, item.size, item.segmentCount);
        }


        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::Close()) {
        DBG_LOG("[epk2] Close\n");

        _inStream.Release();
        _items.Clear();
        _headerSize = 0;
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback)) {
        DBG_LOG("[epk2] Extract\n");

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
        DBG_LOG("[epk2] total size: %llu\n", totalSize);
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
                Byte pakSignature[SIGNATURE_SIZE];
                RINOK(ReadStream_FALSE(_inStream, pakSignature, SIGNATURE_SIZE));

                Byte pakHdrB[sizeof(PakHeader)];
                RINOK(ReadStream_FALSE(_inStream, pakHdrB, sizeof(PakHeader)));

                //decrypt pak header
                decryptAES128ecbUnalign(pakHdrB, sizeof(PakHeader), _key);
                PakHeader pakHdr;
                memcpy(&pakHdr, pakHdrB, sizeof(PakHeader));

                if (memcmp(pakHdr.pakMagic, pakMagic, 4) != 0) {
                    DBG_LOG("[epk2] fail pak signature\n");
                    isOk = false;
                }

                DBG_LOG("[epk2] pak %.*s - segment: %i/%i, seg.size: %i\n", 4, pakHdr.pakName, pakHdr.segmentIndex, pakHdr.segmentCount, pakHdr.segmentSize);

                std::vector<Byte> segmentData(pakHdr.segmentSize);
                RINOK(ReadStream_FALSE(_inStream, segmentData.data(), pakHdr.segmentSize));
                //decrypt data
                decryptAES128ecbUnalign(segmentData.data(), pakHdr.segmentSize, _key);

                //write decrypted segment to output stream
                UInt32 written;
                RINOK(realOutStream->Write(segmentData.data(), segmentData.size(), &written));
                if (written != segmentData.size()) {
                    DBG_LOG("[epk2] fail pak written size\n");
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
        DBG_LOG("[epk2] GetNumberOfItems\n");

        *numItems = _items.Size();
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)) {
        DBG_LOG("[epk2] GetArchiveProperty (propID=%lu)\n", propID);

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
        DBG_LOG("[epk2] GetProperty (index=%i, propID=%lu)\n", index, propID);

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
                prop = item.size - (item.segmentCount * sizeof(PakHeader));
                break;
            case kpidPackSize:
                prop = item.size;
                break;
            case kpidOffset:
                prop = item.offset;
                break;
            case kpidComment:
                Utf8StringToProp(item.platformID, prop);
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
        DBG_LOG("[epk2] GetStream\n");

        *stream = NULL;
        COM_TRY_BEGIN

        const CItem& item = _items[index];
        return CreateLimitedInStream(_inStream, item.offset, item.size, stream);

        COM_TRY_END
    }
    
    Z7_COM7F_IMF(CHandler::GetFileTimeType(UInt32* type)) {
        DBG_LOG("[epk2] GetFileTimeType\n");

        *type = k_PropVar_TimePrec_0;
        return S_OK;
    }

    Z7_COM7F_IMF(CHandler::UpdateItems(ISequentialOutStream* outStream, UInt32 numItems, IArchiveUpdateCallback* callback )) {
        DBG_LOG("[epk2] UpdateItems\n");

        COM_TRY_BEGIN
        return S_OK;
        COM_TRY_END
    }

    //no signature register because of crypted header cannot check signature before decryption logic
    REGISTER_ARC_I_NO_SIG(
        "epk2", // format name
        "epk",  // file extension
        NULL,   // ?ae
        0xA2,   // unique id for GUID
        0,  //offset of signature ? even thogh it shouldnt be used here..
        0,  // arc flags
        0   // isArc
    )

    //register format
    //REGISTER_ARC_I(
    //    "epk2",                 // format name
    //    "epk",                  // file extension
    //    NULL,                   // ?ae
    //    0xA2,                   // unique id for GUID
    //    epk2_Magic,            // file magic signature
    //    140,                      // offset of signature
    //    0,                      // arc flags
    //    0                       // isArc
    //)
}