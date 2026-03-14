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
    #if FMTFIX
    {
    #endif
        CMyComPtr<IInStream> _inStream;
        CObjectVector<CItem> _items;
        UInt64 _headerSize;
        uint8_t _version[4];
        std::string _otaID;
        uint8_t _key[16];
        UInt32 _signatureSize;
        bool _isNewType;

        AString _platformVersion;
        AString _sdkVersion;

        //exhdr 
        AString _updateType;
        AString _encryptType;
        float  _updatePlatformVersion;
        float  _compatibleMinimumVersion;
        int    _needToCheckCompatibleVersion;

        HRESULT Open2(IInStream* stream);
    };

    // specifies the avaliable properties of the archive itself
    static const Byte kArcProps[] = {
        kpidHeadersSize,
        kpidComment,        //used for OTAID + ver

        //CUSTOM
        cIsNewType,
        cplatformVersion,
        cSdkVersion,
        cencryptType,
        cupdateType,
        cupdatePlatformVersion,
        ccompatibleMinimumVersion,
        cneedToCheckCompatibleVersion,
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
        //try to find key for old type (128 signature)
        Byte hdrBuf[MAX_HDR_SIZE];

        RINOK(InStream_SeekSet(stream, 128));
        size_t headerReadSize = MAX_HDR_SIZE - 128;
        RINOK(ReadStream_FALSE(stream, hdrBuf, headerReadSize));

        const uint8_t* key = tryFindAESkey(hdrBuf, headerReadSize, epk3_Magic, sizeof(epk3_Magic), 0);
        if (key) {
            DBG_LOG("[epk3] matched key: ");
            for (int i = 0; i < 16; i++) {
                DBG_LOG("%02X ", key[i]);
            }    
            DBG_LOG("\n");
            _signatureSize = 128;
            _isNewType = false;
            memcpy(_key, key, 16);
        } else {
            //no key found for old type (128 signature), now try new type (256 signature)
            RINOK(InStream_SeekSet(stream, 256));
            headerReadSize = MAX_HDR_SIZE - 256;
            RINOK(ReadStream_FALSE(stream, hdrBuf, headerReadSize));

            key = tryFindAESkey(hdrBuf, headerReadSize, epk3_Magic, sizeof(epk3_Magic), 0);
            if (key) {
                DBG_LOG("[epk3] matched key: ");
                for (int i = 0; i < 16; i++) {
                    DBG_LOG("%02X ", key[i]);
                }    
                DBG_LOG("\n");
                _signatureSize = 256;
                _isNewType = true;
                memcpy(_key, key, 16);
            } else {
                //no key found for both types, return false
                DBG_LOG("[epk3] not found key...\n");
                return S_FALSE;
            } 
        }
    
        // ---------------------

        //decrypt header
        decryptAES128ecbUnalign(hdrBuf, headerReadSize, _key);
        Header header;
        memcpy(&header, hdrBuf, sizeof(header));

        DBG_LOG("[epk3] version %02x.%02x.%02x.%02x\n", header.version[3], header.version[2], header.version[1], header.version[0]);
        memcpy(_version, header.version, sizeof(_version));
        std::string otaID = header.otaID;

        DBG_LOG("[epk3] otaID %s\n", otaID.c_str());
        _otaID = otaID;

        DBG_LOG("[epk3] packageInfoSize %i\n", header.packageInfoSize);

        //ex header for new type
        if (_isNewType) {
            HeaderNewEx exHeader;
            memcpy(&exHeader, hdrBuf + sizeof(Header), sizeof(HeaderNewEx));

            char encryptType[7];
            memcpy(encryptType, exHeader.encryptType, 6);
            encryptType[6] = '\0';
            DBG_LOG("[epk3] encryptType %s\n", encryptType);
            AString aencryptType(encryptType);
            _encryptType = aencryptType;

            char updateType[7];
            memcpy(updateType, exHeader.updateType, 6);
            updateType[6] = '\0';
            DBG_LOG("[epk3] updateType %s\n", updateType);
            AString aupdateType(updateType);
            _updateType = aupdateType;

            DBG_LOG("[epk3] updatePlatformVersion %f\n", exHeader.updatePlatformVersion);
            _updatePlatformVersion = exHeader.updatePlatformVersion;

            DBG_LOG("[epk3] compatibleMinimumVersion %f\n", exHeader.compatibleMinimumVersion);
            _compatibleMinimumVersion = exHeader.compatibleMinimumVersion;

            DBG_LOG("[epk3] needToCheckCompatibleVersion %d\n", exHeader.needToCheckCompatibleVersion);
            _needToCheckCompatibleVersion = exHeader.needToCheckCompatibleVersion;
        }

        //read platform versions
        RINOK(InStream_SeekSet(stream, _signatureSize + headerReadSize));
        Byte verBuf[sizeof(PlatformVersions)];
        RINOK(ReadStream_FALSE(stream, verBuf, sizeof(PlatformVersions)));
        PlatformVersions vers;
        memcpy(&vers, verBuf, sizeof(PlatformVersions));

        DBG_LOG("[epk3] platformVersion %s\n", vers.platformVersion);
        AString platformVersion(vers.platformVersion);
        _platformVersion = platformVersion;

        DBG_LOG("[epk3] sdkVersion %s\n", vers.sdkVersion);
        AString sdkVersion(vers.sdkVersion);
        _sdkVersion = sdkVersion;
        
        _items.Clear();

        //read and decrypt pkginfo
        RINOK(InStream_SeekSet(stream, _signatureSize + headerReadSize + 36 + _signatureSize));
        std::vector<Byte> pkgInfo(header.packageInfoSize);
        RINOK(ReadStream_FALSE(stream, pkgInfo.data(), header.packageInfoSize));
        decryptAES128ecbUnalign(pkgInfo.data(), header.packageInfoSize, _key);

        PkgInfoHeader pkgInfoHeader;
        memcpy(&pkgInfoHeader, pkgInfo.data(), sizeof(pkgInfoHeader));
        DBG_LOG("[epk3] pkgInfo listSize %i\n", pkgInfoHeader.packageInfoListSize);
        DBG_LOG("[epk3] pkgInfo count %i\n", pkgInfoHeader.packageInfoCount);

        int entryIdx = 0;
        int pakIdx = 0;
        int pkgInfoHeaderExtra = _isNewType? 4 : 0;
        int offset = _signatureSize + headerReadSize + 36 + _signatureSize + header.packageInfoSize;
        while (entryIdx < pkgInfoHeader.packageInfoCount) {
            PkgInfoEntry entry;
            memcpy(&entry, pkgInfo.data() + sizeof(PkgInfoHeader) + pkgInfoHeaderExtra + (entryIdx*sizeof(PkgInfoEntry)), sizeof(entry));

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
                    memcpy(&entry, pkgInfo.data() + sizeof(PkgInfoHeader) + pkgInfoHeaderExtra + (entryIdx*sizeof(PkgInfoEntry)), sizeof(entry));
                }
                DBG_LOG("[epk3] seg %i/%i, size: %i\n", entry.segmentIndex, entry.segmentCount, entry.segmentSize);
                offset += _signatureSize + entry.segmentSize;
                if (_isNewType) {
                    offset += 4;
                }

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
                if (_isNewType) {
                    readSize += 4;
                }

                std::vector<Byte> pakSignature(_signatureSize);
                RINOK(ReadStream_FALSE(_inStream, pakSignature.data(), _signatureSize));

                std::vector<Byte> segmentData(readSize);
                RINOK(ReadStream_FALSE(_inStream, segmentData.data(), readSize));
                //decrypt data
                decryptAES128ecbUnalign(segmentData.data(), readSize, _key);

                //write decrypted segment to output stream
                UInt32 written;
                size_t writeSize = segmentData.size();
                const Byte* writeData = segmentData.data();
                if (_isNewType) {
                    writeData += 4;
                    writeSize -= 4;
                }
                RINOK(realOutStream->Write(writeData, writeSize, &written));
                if (written != writeSize) {
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
 
    Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream** stream)) {
        DBG_LOG("[epk3] GetStream\n");

        //no need, if there is no stream it will just use extract function
        return S_OK;
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

            case cIsNewType:
                prop = _isNewType;
                break;
            case cplatformVersion:
                Utf8StringToProp(_platformVersion, prop);
                break;
            case cSdkVersion:
                Utf8StringToProp(_sdkVersion, prop);
                break;

            case cencryptType:
                if (_isNewType) {
                    Utf8StringToProp(_encryptType, prop);
                };
                break;
            case cupdateType:
                if (_isNewType) {
                    Utf8StringToProp(_updateType, prop);
                };
                break;
            case cupdatePlatformVersion:
                if (_isNewType) {
                    char buf[10];
                    sprintf(buf, "%f", _updatePlatformVersion);
                    AString ver(buf);
                    Utf8StringToProp(ver, prop);
                };
                break;
            case ccompatibleMinimumVersion:
                if (_isNewType) {
                    char buf[10];
                    sprintf(buf, "%f", _compatibleMinimumVersion);
                    AString ver(buf);
                    Utf8StringToProp(ver, prop);
                };
                break;
            case cneedToCheckCompatibleVersion:
                if (_isNewType) {
                    prop = (UInt32)_needToCheckCompatibleVersion;
                }
                break;
                
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
}