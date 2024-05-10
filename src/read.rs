//! Types for reading ZIP archives

#[cfg(feature = "aes-crypto")]
use crate::aes::{AesReader, AesReaderValid};
use crate::compression::CompressionMethod;
use crate::cp437::FromCp437;
use crate::crc32::Crc32Reader;
use crate::extra_fields::{ExtendedTimestamp, ExtraField};
use crate::read::zip_archive::Shared;
use crate::result::{ZipError, ZipResult};
use crate::spec;
use crate::types::{AesMode, AesVendorVersion, DateTime, System, ZipFileData};
use crate::zipcrypto::{ZipCryptoReader, ZipCryptoReaderValid, ZipCryptoValidator};
use indexmap::IndexMap;
use std::borrow::{Borrow, Cow};
use std::cell::UnsafeCell;
use std::cmp;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, copy, prelude::*, sink};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[cfg(any(
    feature = "deflate",
    feature = "deflate-zlib",
    feature = "deflate-zlib-ng"
))]
use flate2::read::DeflateDecoder;

#[cfg(feature = "deflate64")]
use deflate64::Deflate64Decoder;

#[cfg(feature = "bzip2")]
use bzip2::read::BzDecoder;

#[cfg(feature = "zstd")]
use zstd::stream::read::Decoder as ZstdDecoder;

/// Provides high level API for reading from a stream.
pub(crate) mod stream;

#[cfg(feature = "lzma")]
pub(crate) mod lzma;

// Put the struct declaration in a private module to convince rustdoc to display ZipArchive nicely
pub(crate) mod zip_archive {
    use std::sync::Arc;

    /// Extract immutable data from `ZipArchive` to make it cheap to clone
    #[derive(Debug)]
    pub(crate) struct Shared {
        pub(crate) files: super::IndexMap<Box<str>, super::ZipFileData>,
        pub(super) offset: u64,
        pub(super) dir_start: u64,
    }

    /// ZIP archive reader
    ///
    /// At the moment, this type is cheap to clone if this is the case for the
    /// reader it uses. However, this is not guaranteed by this crate and it may
    /// change in the future.
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    /// fn list_zip_contents(reader: impl Read + Seek) -> zip::result::ZipResult<()> {
    ///     let mut zip = zip::ZipArchive::new(reader)?;
    ///
    ///     for i in 0..zip.len() {
    ///         let mut file = zip.by_index(i)?;
    ///         println!("Filename: {}", file.name());
    ///         std::io::copy(&mut file, &mut std::io::stdout())?;
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    #[derive(Clone, Debug)]
    pub struct ZipArchive<R> {
        pub(super) reader: R,
        pub(super) shared: Arc<Shared>,
        pub(super) comment: Arc<[u8]>,
    }
}

#[cfg(feature = "lzma")]
use crate::read::lzma::LzmaDecoder;
use crate::result::ZipError::{InvalidPassword, UnsupportedArchive};
use crate::spec::path_to_string;
use crate::unstable::LittleEndianReadExt;
pub use zip_archive::ZipArchive;

#[allow(clippy::large_enum_variant)]
pub(crate) enum CryptoReader<'a> {
    Plaintext(io::Take<&'a mut dyn Read>),
    ZipCrypto(ZipCryptoReaderValid<io::Take<&'a mut dyn Read>>),
    #[cfg(feature = "aes-crypto")]
    Aes {
        reader: AesReaderValid<io::Take<&'a mut dyn Read>>,
        vendor_version: AesVendorVersion,
    },
}

impl<'a> Read for CryptoReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            CryptoReader::Plaintext(r) => r.read(buf),
            CryptoReader::ZipCrypto(r) => r.read(buf),
            #[cfg(feature = "aes-crypto")]
            CryptoReader::Aes { reader: r, .. } => r.read(buf),
        }
    }
}

impl<'a> CryptoReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> io::Take<&'a mut dyn Read> {
        match self {
            CryptoReader::Plaintext(r) => r,
            CryptoReader::ZipCrypto(r) => r.into_inner(),
            #[cfg(feature = "aes-crypto")]
            CryptoReader::Aes { reader: r, .. } => r.into_inner(),
        }
    }

    /// Returns `true` if the data is encrypted using AE2.
    pub const fn is_ae2_encrypted(&self) -> bool {
        #[cfg(feature = "aes-crypto")]
        return matches!(
            self,
            CryptoReader::Aes {
                vendor_version: AesVendorVersion::Ae2,
                ..
            }
        );
        #[cfg(not(feature = "aes-crypto"))]
        false
    }
}

enum ZipEntry<'a, R: Read + 'a> {
    Stored(R),
    #[cfg(any(
        feature = "deflate",
        feature = "deflate-miniz",
        feature = "deflate-zlib"
    ))]
    Deflated(flate2::read::DeflateDecoder<R>),
    #[cfg(feature = "bzip2")]
    Bzip2(BzDecoder<R>),
    #[cfg(feature = "zstd")]
    Zstd(ZstdDecoder<'a, io::BufReader<R>>),
}

impl<'a, R: Read + 'a> ZipEntry<'a, R> {
    pub fn from_data(data: &'a ZipFileData, source_handle: R) -> Self {
        match data.compression_method {
            CompressionMethod::Stored => Self::Stored(source_handle),
            #[cfg(any(
                feature = "deflate",
                feature = "deflate-miniz",
                feature = "deflate-zlib"
            ))]
            CompressionMethod::Deflated => Self::Deflated(DeflateDecoder::new(source_handle)),
            #[cfg(feature = "bzip2")]
            CompressionMethod::Bzip2 => Self::Bzip2(BzDecoder::new(source_handle)),
            #[cfg(feature = "zstd")]
            CompressionMethod::Zstd => {
                let zstd_reader = ZstdDecoder::new(source_handle).unwrap();
                Self::Zstd(zstd_reader)
            }
            _ => panic!("Compression method not supported"),
        }
    }
}

impl<'a, R: Read + 'a> Read for ZipEntry<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stored(r) => r.read(buf),
            #[cfg(any(
                feature = "deflate",
                feature = "deflate-miniz",
                feature = "deflate-zlib"
            ))]
            Self::Deflated(r) => r.read(buf),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(r) => r.read(buf),
            #[cfg(feature = "zstd")]
            Self::Zstd(r) => r.read(buf),
        }
    }
}

pub(crate) enum ZipFileReader<'a> {
    NoReader,
    Raw(io::Take<&'a mut dyn Read>),
    Stored(Crc32Reader<CryptoReader<'a>>),
    #[cfg(feature = "_deflate-any")]
    Deflated(Crc32Reader<DeflateDecoder<CryptoReader<'a>>>),
    #[cfg(feature = "deflate64")]
    Deflate64(Crc32Reader<Deflate64Decoder<io::BufReader<CryptoReader<'a>>>>),
    #[cfg(feature = "bzip2")]
    Bzip2(Crc32Reader<BzDecoder<CryptoReader<'a>>>),
    #[cfg(feature = "zstd")]
    Zstd(Crc32Reader<ZstdDecoder<'a, io::BufReader<CryptoReader<'a>>>>),
    #[cfg(feature = "lzma")]
    Lzma(Crc32Reader<Box<LzmaDecoder<CryptoReader<'a>>>>),
}

impl<'a> Read for ZipFileReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ZipFileReader::NoReader => panic!("ZipFileReader was in an invalid state"),
            ZipFileReader::Raw(r) => r.read(buf),
            ZipFileReader::Stored(r) => r.read(buf),
            #[cfg(feature = "_deflate-any")]
            ZipFileReader::Deflated(r) => r.read(buf),
            #[cfg(feature = "deflate64")]
            ZipFileReader::Deflate64(r) => r.read(buf),
            #[cfg(feature = "bzip2")]
            ZipFileReader::Bzip2(r) => r.read(buf),
            #[cfg(feature = "zstd")]
            ZipFileReader::Zstd(r) => r.read(buf),
            #[cfg(feature = "lzma")]
            ZipFileReader::Lzma(r) => r.read(buf),
        }
    }
}

impl<'a> ZipFileReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn drain(self) {
        let mut inner = match self {
            ZipFileReader::NoReader => panic!("ZipFileReader was in an invalid state"),
            ZipFileReader::Raw(r) => r,
            ZipFileReader::Stored(r) => r.into_inner().into_inner(),
            #[cfg(feature = "_deflate-any")]
            ZipFileReader::Deflated(r) => r.into_inner().into_inner().into_inner(),
            #[cfg(feature = "deflate64")]
            ZipFileReader::Deflate64(r) => r.into_inner().into_inner().into_inner().into_inner(),
            #[cfg(feature = "bzip2")]
            ZipFileReader::Bzip2(r) => r.into_inner().into_inner().into_inner(),
            #[cfg(feature = "zstd")]
            ZipFileReader::Zstd(r) => r.into_inner().finish().into_inner().into_inner(),
            #[cfg(feature = "lzma")]
            ZipFileReader::Lzma(r) => {
                // Lzma reader owns its buffer rather than mutably borrowing it, so we have to drop
                // it separately
                if let Ok(mut remaining) = r.into_inner().finish() {
                    let _ = copy(&mut remaining, &mut sink());
                }
                return;
            }
        };
        let _ = copy(&mut inner, &mut sink());
    }
}

/// A struct for reading a zip file
pub struct ZipFile<'a> {
    pub(crate) data: Cow<'a, ZipFileData>,
    pub(crate) crypto_reader: Option<CryptoReader<'a>>,
    pub(crate) reader: ZipFileReader<'a>,
}

pub(crate) fn find_content<'a>(
    data: &ZipFileData,
    reader: &'a mut (impl Read + Seek),
) -> ZipResult<io::Take<&'a mut dyn Read>> {
    // Parse local header
    reader.seek(io::SeekFrom::Start(data.header_start))?;
    let signature = reader.read_u32_le()?;
    if signature != spec::LOCAL_FILE_HEADER_SIGNATURE {
        return Err(ZipError::InvalidArchive("Invalid local file header"));
    }
    let data_start = match data.data_start.get() {
        None => {
            reader.seek(io::SeekFrom::Current(22))?;
            let file_name_length = reader.read_u16_le()? as u64;
            let extra_field_length = reader.read_u16_le()? as u64;
            let magic_and_header = 4 + 22 + 2 + 2;
            let data_start =
                data.header_start + magic_and_header + file_name_length + extra_field_length;
            data.data_start.get_or_init(|| data_start);
            data_start
        }
        Some(start) => *start,
    };

    reader.seek(io::SeekFrom::Start(data_start))?;
    Ok((reader as &mut dyn Read).take(data.compressed_size))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_crypto_reader<'a>(
    compression_method: CompressionMethod,
    crc32: u32,
    last_modified_time: DateTime,
    using_data_descriptor: bool,
    reader: io::Take<&'a mut dyn Read>,
    password: Option<&[u8]>,
    aes_info: Option<(AesMode, AesVendorVersion, CompressionMethod)>,
    #[cfg(feature = "aes-crypto")] compressed_size: u64,
) -> ZipResult<CryptoReader<'a>> {
    #[allow(deprecated)]
    {
        if let CompressionMethod::Unsupported(_) = compression_method {
            return unsupported_zip_error("Compression method not supported");
        }
    }

    let reader = match (password, aes_info) {
        #[cfg(not(feature = "aes-crypto"))]
        (Some(_), Some(_)) => {
            return Err(ZipError::UnsupportedArchive(
                "AES encrypted files cannot be decrypted without the aes-crypto feature.",
            ))
        }
        #[cfg(feature = "aes-crypto")]
        (Some(password), Some((aes_mode, vendor_version, _))) => CryptoReader::Aes {
            reader: AesReader::new(reader, aes_mode, compressed_size).validate(password)?,
            vendor_version,
        },
        (Some(password), None) => {
            let validator = if using_data_descriptor {
                ZipCryptoValidator::InfoZipMsdosTime(last_modified_time.timepart())
            } else {
                ZipCryptoValidator::PkzipCrc32(crc32)
            };
            CryptoReader::ZipCrypto(ZipCryptoReader::new(reader, password).validate(validator)?)
        }
        (None, Some(_)) => return Err(InvalidPassword),
        (None, None) => CryptoReader::Plaintext(reader),
    };
    Ok(reader)
}

pub(crate) fn make_reader(
    compression_method: CompressionMethod,
    crc32: u32,
    reader: CryptoReader,
) -> ZipResult<ZipFileReader> {
    let ae2_encrypted = reader.is_ae2_encrypted();

    match compression_method {
        CompressionMethod::Stored => Ok(ZipFileReader::Stored(Crc32Reader::new(
            reader,
            crc32,
            ae2_encrypted,
        ))),
        #[cfg(feature = "_deflate-any")]
        CompressionMethod::Deflated => {
            let deflate_reader = DeflateDecoder::new(reader);
            Ok(ZipFileReader::Deflated(Crc32Reader::new(
                deflate_reader,
                crc32,
                ae2_encrypted,
            )))
        }
        #[cfg(feature = "deflate64")]
        CompressionMethod::Deflate64 => {
            let deflate64_reader = Deflate64Decoder::new(reader);
            Ok(ZipFileReader::Deflate64(Crc32Reader::new(
                deflate64_reader,
                crc32,
                ae2_encrypted,
            )))
        }
        #[cfg(feature = "bzip2")]
        CompressionMethod::Bzip2 => {
            let bzip2_reader = BzDecoder::new(reader);
            Ok(ZipFileReader::Bzip2(Crc32Reader::new(
                bzip2_reader,
                crc32,
                ae2_encrypted,
            )))
        }
        #[cfg(feature = "zstd")]
        CompressionMethod::Zstd => {
            let zstd_reader = ZstdDecoder::new(reader).unwrap();
            Ok(ZipFileReader::Zstd(Crc32Reader::new(
                zstd_reader,
                crc32,
                ae2_encrypted,
            )))
        }
        #[cfg(feature = "lzma")]
        CompressionMethod::Lzma => {
            let reader = LzmaDecoder::new(reader);
            Ok(ZipFileReader::Lzma(Crc32Reader::new(
                Box::new(reader),
                crc32,
                ae2_encrypted,
            )))
        }
        _ => Err(UnsupportedArchive("Compression method not supported")),
    }
}

pub(crate) struct CentralDirectoryInfo {
    pub(crate) archive_offset: u64,
    pub(crate) directory_start: u64,
    pub(crate) number_of_files: usize,
    pub(crate) disk_number: u32,
    pub(crate) disk_with_central_directory: u32,
}

impl<R> ZipArchive<R> {
    pub(crate) fn from_finalized_writer(
        files: IndexMap<Box<str>, ZipFileData>,
        comment: Box<[u8]>,
        reader: R,
        central_start: u64,
    ) -> ZipResult<Self> {
        let initial_offset = match files.first() {
            Some((_, file)) => file.header_start,
            None => 0,
        };
        let shared = Arc::new(zip_archive::Shared {
            files,
            offset: initial_offset,
            dir_start: central_start,
        });
        Ok(Self {
            reader,
            shared,
            comment: comment.into(),
        })
    }

    /// Total size of the files in the archive, if it can be known. Doesn't include directories or
    /// metadata.
    pub fn decompressed_size(&self) -> Option<u128> {
        let mut total = 0u128;
        for file in self.shared.files.values() {
            if file.using_data_descriptor {
                return None;
            }
            total = total.checked_add(file.uncompressed_size as u128)?;
        }
        Some(total)
    }
}

impl<R: Read + Seek> ZipArchive<R> {
    pub(crate) fn merge_contents<W: Write + io::Seek>(
        &mut self,
        mut w: W,
    ) -> ZipResult<IndexMap<Box<str>, ZipFileData>> {
        if self.shared.files.is_empty() {
            return Ok(IndexMap::new());
        }
        let mut new_files = self.shared.files.clone();
        /* The first file header will probably start at the beginning of the file, but zip doesn't
         * enforce that, and executable zips like PEX files will have a shebang line so will
         * definitely be greater than 0.
         *
         * assert_eq!(0, new_files[0].header_start); // Avoid this.
         */

        let new_initial_header_start = w.stream_position()?;
        /* Push back file header starts for all entries in the covered files. */
        new_files.values_mut().try_for_each(|f| {
            /* This is probably the only really important thing to change. */
            f.header_start = f.header_start.checked_add(new_initial_header_start).ok_or(
                ZipError::InvalidArchive("new header start from merge would have been too large"),
            )?;
            /* This is only ever used internally to cache metadata lookups (it's not part of the
             * zip spec), and 0 is the sentinel value. */
            f.central_header_start = 0;
            /* This is an atomic variable so it can be updated from another thread in the
             * implementation (which is good!). */
            if let Some(old_data_start) = f.data_start.take() {
                let new_data_start = old_data_start.checked_add(new_initial_header_start).ok_or(
                    ZipError::InvalidArchive("new data start from merge would have been too large"),
                )?;
                f.data_start.get_or_init(|| new_data_start);
            }
            Ok::<_, ZipError>(())
        })?;

        /* Rewind to the beginning of the file.
         *
         * NB: we *could* decide to start copying from new_files[0].header_start instead, which
         * would avoid copying over e.g. any pex shebangs or other file contents that start before
         * the first zip file entry. However, zip files actually shouldn't care about garbage data
         * in *between* real entries, since the central directory header records the correct start
         * location of each, and keeping track of that math is more complicated logic that will only
         * rarely be used, since most zips that get merged together are likely to be produced
         * specifically for that purpose (and therefore are unlikely to have a shebang or other
         * preface). Finally, this preserves any data that might actually be useful.
         */
        self.reader.rewind()?;
        /* Find the end of the file data. */
        let length_to_read = self.shared.dir_start;
        /* Produce a Read that reads bytes up until the start of the central directory header.
         * This "as &mut dyn Read" trick is used elsewhere to avoid having to clone the underlying
         * handle, which it really shouldn't need to anyway. */
        let mut limited_raw = (&mut self.reader as &mut dyn Read).take(length_to_read);
        /* Copy over file data from source archive directly. */
        io::copy(&mut limited_raw, &mut w)?;

        /* Return the files we've just written to the data stream. */
        Ok(new_files)
    }

    fn get_directory_info_zip32(
        footer: &spec::CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<CentralDirectoryInfo> {
        // Some zip files have data prepended to them, resulting in the
        // offsets all being too small. Get the amount of error by comparing
        // the actual file position we found the CDE at with the offset
        // recorded in the CDE.
        let archive_offset = cde_start_pos
            .checked_sub(footer.central_directory_size as u64)
            .and_then(|x| x.checked_sub(footer.central_directory_offset as u64))
            .ok_or(ZipError::InvalidArchive(
                "Invalid central directory size or offset",
            ))?;

        let directory_start = footer.central_directory_offset as u64 + archive_offset;
        let number_of_files = footer.number_of_files_on_this_disk as usize;
        Ok(CentralDirectoryInfo {
            archive_offset,
            directory_start,
            number_of_files,
            disk_number: footer.disk_number as u32,
            disk_with_central_directory: footer.disk_with_central_directory as u32,
        })
    }

    fn get_directory_info_zip64(
        reader: &mut R,
        footer: &spec::CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<Vec<ZipResult<CentralDirectoryInfo>>> {
        // See if there's a ZIP64 footer. The ZIP64 locator if present will
        // have its signature 20 bytes in front of the standard footer. The
        // standard footer, in turn, is 22+N bytes large, where N is the
        // comment length. Therefore:
        reader.seek(io::SeekFrom::End(
            -(20 + 22 + footer.zip_file_comment.len() as i64),
        ))?;
        let locator64 = spec::Zip64CentralDirectoryEndLocator::parse(reader)?;

        // We need to reassess `archive_offset`. We know where the ZIP64
        // central-directory-end structure *should* be, but unfortunately we
        // don't know how to precisely relate that location to our current
        // actual offset in the file, since there may be junk at its
        // beginning. Therefore we need to perform another search, as in
        // read::CentralDirectoryEnd::find_and_parse, except now we search
        // forward. There may be multiple results because of Zip64 central-directory signatures in
        // ZIP comment data.

        let mut results = Vec::new();

        let search_upper_bound = cde_start_pos
            .checked_sub(60) // minimum size of Zip64CentralDirectoryEnd + Zip64CentralDirectoryEndLocator
            .ok_or(ZipError::InvalidArchive(
                "File cannot contain ZIP64 central directory end",
            ))?;
        let search_results = spec::Zip64CentralDirectoryEnd::find_and_parse(
            reader,
            locator64.end_of_central_directory_offset,
            search_upper_bound,
        )?;
        search_results.into_iter().for_each(|(footer64, archive_offset)| {
            results.push({
                let directory_start_result = footer64
                    .central_directory_offset
                    .checked_add(archive_offset)
                    .ok_or(ZipError::InvalidArchive(
                        "Invalid central directory size or offset",
                    ));
                directory_start_result.and_then(|directory_start| {
                    if directory_start > search_upper_bound {
                        Err(ZipError::InvalidArchive(
                            "Invalid central directory size or offset",
                        ))
                    } else if footer64.number_of_files_on_this_disk > footer64.number_of_files {
                        Err(ZipError::InvalidArchive(
                            "ZIP64 footer indicates more files on this disk than in the whole archive",
                        ))
                    } else if footer64.version_needed_to_extract > footer64.version_made_by {
                        Err(ZipError::InvalidArchive(
                            "ZIP64 footer indicates a new version is needed to extract this archive than the \
    version that wrote it",
                        ))
                    } else {
                        Ok(CentralDirectoryInfo {
                            archive_offset,
                            directory_start,
                            number_of_files: footer64.number_of_files as usize,
                            disk_number: footer64.disk_number,
                            disk_with_central_directory: footer64.disk_with_central_directory,
                        })
                    }
                })
            });
        });
        Ok(results)
    }

    /// Get the directory start offset and number of files. This is done in a
    /// separate function to ease the control flow design.
    pub(crate) fn get_metadata(
        reader: &mut R,
        footer: &spec::CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<Shared> {
        // Check if file has a zip64 footer
        let mut results = Self::get_directory_info_zip64(reader, footer, cde_start_pos)
            .unwrap_or_else(|e| vec![Err(e)]);
        let zip32_result = Self::get_directory_info_zip32(footer, cde_start_pos);
        let mut invalid_errors = Vec::new();
        let mut unsupported_errors = Vec::new();
        let mut ok_results = Vec::new();
        results.iter_mut().for_each(|result| {
            if let Ok(central_dir) = result {
                if let Ok(zip32_central_dir) = &zip32_result {
                    // Both zip32 and zip64 footers exist, so check if the zip64 footer is valid; if not, try zip32
                    if central_dir.number_of_files != zip32_central_dir.number_of_files
                        && zip32_central_dir.number_of_files != u16::MAX as usize
                    {
                        *result = Err(ZipError::InvalidArchive(
                            "ZIP32 and ZIP64 file counts don't match",
                        ));
                        return;
                    }
                    if central_dir.disk_number != zip32_central_dir.disk_number
                        && zip32_central_dir.disk_number != u16::MAX as u32
                    {
                        *result = Err(ZipError::InvalidArchive(
                            "ZIP32 and ZIP64 disk numbers don't match",
                        ));
                        return;
                    }
                    if central_dir.disk_with_central_directory
                        != zip32_central_dir.disk_with_central_directory
                        && zip32_central_dir.disk_with_central_directory != u16::MAX as u32
                    {
                        *result = Err(ZipError::InvalidArchive(
                            "ZIP32 and ZIP64 last-disk numbers don't match",
                        ));
                    }
                }
            }
        });
        results.push(zip32_result);
        results
            .into_iter()
            .map(|result| {
                result.and_then(|dir_info| {
                    // If the parsed number of files is greater than the offset then
                    // something fishy is going on and we shouldn't trust number_of_files.
                    let file_capacity =
                        if dir_info.number_of_files > dir_info.directory_start as usize {
                            0
                        } else {
                            dir_info.number_of_files
                        };
                    let mut files = IndexMap::with_capacity(file_capacity);
                    reader.seek(io::SeekFrom::Start(dir_info.directory_start))?;
                    for _ in 0..dir_info.number_of_files {
                        let file = central_header_to_zip_file(reader, dir_info.archive_offset)?;
                        files.insert(file.file_name.clone(), file);
                    }
                    if dir_info.disk_number != dir_info.disk_with_central_directory {
                        unsupported_zip_error("Support for multi-disk files is not implemented")
                    } else {
                        Ok(Shared {
                            files,
                            offset: dir_info.archive_offset,
                            dir_start: dir_info.directory_start,
                        })
                    }
                })
            })
            .for_each(|result| match result {
                Err(ZipError::UnsupportedArchive(e)) => {
                    unsupported_errors.push(ZipError::UnsupportedArchive(e))
                }
                Err(e) => invalid_errors.push(e),
                Ok(o) => ok_results.push(o),
            });
        if ok_results.is_empty() {
            return Err(unsupported_errors
                .into_iter()
                .next()
                .unwrap_or_else(|| invalid_errors.into_iter().next().unwrap()));
        }
        let shared = ok_results
            .into_iter()
            .max_by_key(|shared| shared.dir_start)
            .unwrap();
        reader.seek(io::SeekFrom::Start(shared.dir_start))?;
        Ok(shared)
    }

    /// Read a ZIP archive, collecting the files it contains
    ///
    /// This uses the central directory record of the ZIP file, and ignores local file headers
    pub fn new(mut reader: R) -> ZipResult<ZipArchive<R>> {
        let (footer, cde_start_pos) = spec::CentralDirectoryEnd::find_and_parse(&mut reader)?;
        let shared = Self::get_metadata(&mut reader, &footer, cde_start_pos)?;
        Ok(ZipArchive {
            reader,
            shared: shared.into(),
            comment: footer.zip_file_comment.into(),
        })
    }
    /// Extract a Zip archive into a directory, overwriting files if they
    /// already exist. Paths are sanitized with [`ZipFile::enclosed_name`].
    ///
    /// Extraction is not atomic; If an error is encountered, some of the files
    /// may be left on disk.
    pub fn extract<P: AsRef<Path>>(&mut self, directory: P) -> ZipResult<()> {
        for i in 0..self.len() {
            let mut file = self.by_index(i)?;
            let filepath = file
                .enclosed_name()
                .ok_or(ZipError::InvalidArchive("Invalid file path"))?;

            let outpath = directory.as_ref().join(filepath);

            if file.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(p)?;
                    }
                }
                let mut outfile = fs::File::create(&outpath)?;
                io::copy(&mut file, &mut outfile)?;
            }
            // Get and Set permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }
        Ok(())
    }

    /// Number of files contained in this zip.
    pub fn len(&self) -> usize {
        self.shared.files.len()
    }

    /// Whether this zip archive contains no files
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the offset from the beginning of the underlying reader that this zip begins at, in bytes.
    ///
    /// Normally this value is zero, but if the zip has arbitrary data prepended to it, then this value will be the size
    /// of that prepended data.
    pub fn offset(&self) -> u64 {
        self.shared.offset
    }

    /// Get the comment of the zip archive.
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Returns an iterator over all the file and directory names in this archive.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.shared.files.keys().map(|s| s.as_ref())
    }

    /// Search for a file entry by name, decrypt with given password
    ///
    /// # Warning
    ///
    /// The implementation of the cryptographic algorithms has not
    /// gone through a correctness review, and you should assume it is insecure:
    /// passwords used with this API may be compromised.
    ///
    /// This function sometimes accepts wrong password. This is because the ZIP spec only allows us
    /// to check for a 1/256 chance that the password is correct.
    /// There are many passwords out there that will also pass the validity checks
    /// we are able to perform. This is a weakness of the ZipCrypto algorithm,
    /// due to its fairly primitive approach to cryptography.
    pub fn by_name_decrypt(&mut self, name: &str, password: &[u8]) -> ZipResult<ZipFile> {
        self.by_name_with_optional_password(name, Some(password))
    }

    /// Search for a file entry by name
    pub fn by_name(&mut self, name: &str) -> ZipResult<ZipFile> {
        self.by_name_with_optional_password(name, None)
    }

    /// Get the index of a file entry by name, if it's present.
    #[inline(always)]
    pub fn index_for_name(&self, name: &str) -> Option<usize> {
        self.shared.files.get_index_of(name)
    }

    /// Get the index of a file entry by path, if it's present.
    #[inline(always)]
    pub fn index_for_path<T: AsRef<Path>>(&self, path: T) -> Option<usize> {
        self.index_for_name(&path_to_string(path))
    }

    /// Get the name of a file entry, if it's present.
    #[inline(always)]
    pub fn name_for_index(&self, index: usize) -> Option<&str> {
        self.shared
            .files
            .get_index(index)
            .map(|(name, _)| name.as_ref())
    }

    fn by_name_with_optional_password<'a>(
        &'a mut self,
        name: &str,
        password: Option<&[u8]>,
    ) -> ZipResult<ZipFile<'a>> {
        let Some(index) = self.shared.files.get_index_of(name) else {
            return Err(ZipError::FileNotFound);
        };
        self.by_index_with_optional_password(index, password)
    }

    /// Get a contained file by index, decrypt with given password
    ///
    /// # Warning
    ///
    /// The implementation of the cryptographic algorithms has not
    /// gone through a correctness review, and you should assume it is insecure:
    /// passwords used with this API may be compromised.
    ///
    /// This function sometimes accepts wrong password. This is because the ZIP spec only allows us
    /// to check for a 1/256 chance that the password is correct.
    /// There are many passwords out there that will also pass the validity checks
    /// we are able to perform. This is a weakness of the ZipCrypto algorithm,
    /// due to its fairly primitive approach to cryptography.
    pub fn by_index_decrypt(
        &mut self,
        file_number: usize,
        password: &[u8],
    ) -> ZipResult<ZipFile<'_>> {
        self.by_index_with_optional_password(file_number, Some(password))
    }

    /// Get a contained file by index
    pub fn by_index(&mut self, file_number: usize) -> ZipResult<ZipFile<'_>> {
        self.by_index_with_optional_password(file_number, None)
    }

    /// Get a contained file by index without decompressing it
    pub fn by_index_raw(&mut self, file_number: usize) -> ZipResult<ZipFile<'_>> {
        let reader = &mut self.reader;
        let (_, data) = self
            .shared
            .files
            .get_index(file_number)
            .ok_or(ZipError::FileNotFound)?;
        Ok(ZipFile {
            crypto_reader: None,
            reader: ZipFileReader::Raw(find_content(data, reader)?),
            data: Cow::Borrowed(data),
        })
    }

    fn by_index_with_optional_password(
        &mut self,
        file_number: usize,
        mut password: Option<&[u8]>,
    ) -> ZipResult<ZipFile<'_>> {
        let (_, data) = self
            .shared
            .files
            .get_index(file_number)
            .ok_or(ZipError::FileNotFound)?;

        match (password, data.encrypted) {
            (None, true) => return Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)),
            (Some(_), false) => password = None, //Password supplied, but none needed! Discard.
            _ => {}
        }
        let limit_reader = find_content(data, &mut self.reader)?;

        let crypto_reader = make_crypto_reader(
            data.compression_method,
            data.crc32,
            data.last_modified_time,
            data.using_data_descriptor,
            limit_reader,
            password,
            data.aes_mode,
            #[cfg(feature = "aes-crypto")]
            data.compressed_size,
        )?;
        Ok(ZipFile {
            crypto_reader: Some(crypto_reader),
            reader: ZipFileReader::NoReader,
            data: Cow::Borrowed(data),
        })
    }

    /// Unwrap and return the inner reader object
    ///
    /// The position of the reader is undefined.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[derive(Debug, Clone)]
struct CompletedPaths {
    seen: HashSet<PathBuf>,
}

impl CompletedPaths {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    pub fn contains(&self, path: impl AsRef<Path>) -> bool {
        self.seen.contains(path.as_ref())
    }

    pub fn containing_dirs<'a>(
        path: &'a (impl AsRef<Path> + ?Sized),
    ) -> impl Iterator<Item = &'a Path> {
        let is_dir = path.as_ref().to_string_lossy().ends_with('/');
        path.as_ref()
            .ancestors()
            .inspect(|p| {
                if p == &Path::new("/") {
                    unreachable!("did not expect absolute paths")
                }
            })
            .filter_map(move |p| {
                if &p == &path.as_ref() {
                    if is_dir {
                        Some(p)
                    } else {
                        None
                    }
                } else if p == Path::new("") {
                    None
                } else {
                    Some(p)
                }
            })
    }

    pub fn new_containing_dirs_needed<'a>(
        &self,
        path: &'a (impl AsRef<Path> + ?Sized),
    ) -> Vec<&'a Path> {
        let mut ret: Vec<_> = Self::containing_dirs(path)
            /* Assuming we are given ancestors in order from child to parent. */
            .take_while(|p| !self.contains(p))
            .collect();
        /* Get dirs in order from parent to child. */
        ret.reverse();
        ret
    }

    pub fn write_dirs<'a>(&mut self, paths: &[&'a Path]) {
        for path in paths.iter() {
            if !self.contains(path) {
                self.seen.insert(path.to_path_buf());
            }
        }
    }
}

#[derive(Debug)]
#[allow(missing_docs)]
pub enum IntermediateFile {
    Immediate(Arc<RwLock<Box<[u8]>>>, usize),
    Paging(UnsafeCell<fs::File>, PathBuf, usize),
}

unsafe impl Sync for IntermediateFile {}

impl fmt::Display for IntermediateFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let len = self.len();
        match self {
            Self::Immediate(arc, pos) => match str::from_utf8(arc.read().unwrap().as_ref()) {
                Ok(s) => write!(f, "Immediate(@{})[{}](\"{}\")", pos, s.len(), s),
                Err(_) => write!(f, "Immediate[{}](<binary>)", len),
                /* Err(_) => write!( */
                /*     f, */
                /*     "Immediate(@{})[{}](<binary> = \"{}\")", */
                /*     pos, */
                /*     arc.read().unwrap().len(), */
                /*     String::from_utf8_lossy(arc.read().unwrap().as_ref()), */
                /* ), */
            },
            Self::Paging(_, path, len) => write!(f, "Paging[{}]({})", len, path.display()),
        }
    }
}

impl IntermediateFile {
    #[allow(missing_docs)]
    pub fn len(&self) -> usize {
        match self {
            Self::Immediate(arc, _) => arc.read().unwrap().len(),
            Self::Paging(_, _, len) => *len,
        }
    }
    #[allow(missing_docs)]
    pub fn tell(&self) -> io::Result<u64> {
        match self {
            Self::Immediate(_, pos) => Ok(*pos as u64),
            Self::Paging(f, _, _) => {
                let f: &mut fs::File = unsafe { &mut *f.get() };
                Ok(f.stream_position()?)
            }
        }
    }
    #[allow(missing_docs)]
    pub fn immediate(len: usize) -> Self {
        Self::Immediate(Arc::new(RwLock::new(vec![0; len].into_boxed_slice())), 0)
    }
    #[allow(missing_docs)]
    pub fn paging(len: usize) -> io::Result<Self> {
        let f = tempfile::NamedTempFile::with_prefix("intermediate")?;
        let (mut f, path) = f.keep().unwrap();
        f.set_len(len as u64)?;
        f.rewind()?;
        Ok(Self::Paging(UnsafeCell::new(f), path, len))
    }
    #[allow(missing_docs)]
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut f = fs::File::open(path.as_ref())?;
        let len = f.seek(io::SeekFrom::End(0))?;
        f.rewind()?;
        Ok(Self::Paging(
            UnsafeCell::new(f),
            path.as_ref().to_path_buf(),
            len as usize,
        ))
    }
    #[allow(missing_docs)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::Immediate(Arc::new(RwLock::new(bytes.into())), 0)
    }
    #[allow(missing_docs)]
    pub fn remove_backing_file(&mut self) -> io::Result<()> {
        match self {
            Self::Immediate(_, _) => Ok(()),
            Self::Paging(_, path, _) => fs::remove_file(path),
        }
    }
}

impl Clone for IntermediateFile {
    fn clone(&self) -> Self {
        let pos = self.tell().unwrap();
        /* eprintln!("cloning! {}", &self); */
        match self {
            Self::Immediate(arc, pos) => Self::Immediate(arc.clone(), *pos),
            Self::Paging(_, path, len) => {
                /* let prev_f: &mut fs::File = unsafe { &mut *prev_f.get() }; */
                /* prev_f.sync_data().unwrap(); */
                let mut new_f = fs::OpenOptions::new().read(true).open(&path).unwrap();
                new_f.seek(io::SeekFrom::Start(pos)).unwrap();
                Self::Paging(UnsafeCell::new(new_f), path.clone(), *len)
            }
        }
    }
}

impl io::Read for IntermediateFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Immediate(arc, pos) => {
                let beg = *pos;
                let full_len = arc.read().unwrap().as_ref().len();
                assert!(full_len >= beg);
                let end = cmp::min(beg + buf.len(), full_len);
                let src = &arc.read().unwrap()[beg..end];
                let cur_len = src.len();
                buf[..cur_len].copy_from_slice(src);
                *pos += cur_len;
                Ok(cur_len)
            }
            Self::Paging(file, _, _) => file.get_mut().read(buf),
        }
    }
}

impl io::Seek for IntermediateFile {
    fn seek(&mut self, pos_arg: io::SeekFrom) -> io::Result<u64> {
        let len = self.len();
        match self {
            Self::Immediate(_, pos) => {
                match pos_arg {
                    io::SeekFrom::Start(s) => {
                        *pos = s as usize;
                    }
                    io::SeekFrom::End(from_end) => {
                        *pos = ((len as isize) + from_end as isize) as usize;
                    }
                    io::SeekFrom::Current(from_cur) => {
                        *pos = ((*pos as isize) + from_cur as isize) as usize;
                    }
                };
                Ok(*pos as u64)
            }
            Self::Paging(file, _, _) => file.get_mut().seek(pos_arg),
        }
    }
}

impl io::Write for IntermediateFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let full_len = self.len();
        match self {
            Self::Immediate(arc, pos) => {
                let beg = *pos;
                assert!(beg <= full_len);
                let end = cmp::min(beg + buf.len(), full_len);
                let cur_len = end - beg;
                arc.write().unwrap()[beg..end].copy_from_slice(&buf[..cur_len]);
                *pos += cur_len;
                Ok(cur_len)
            }
            Self::Paging(file, _, _) => file.get_mut().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Immediate(_, _) => Ok(()),
            Self::Paging(file, _, _) => file.get_mut().flush(),
        }
    }
}

static NUM_CPUS: OnceLock<usize> = OnceLock::new();

fn build_thread_pool(n: Option<usize>, prefix: &str) -> rayon::ThreadPool {
    let prefix = prefix.to_string();
    let num_cpus = NUM_CPUS.get_or_init(|| 
        match std::thread::available_parallelism() {
            Ok(x) => x.into(),
            /* Default to 2 if any error occurs. */
            Err(_) => 2,
        }
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(n.unwrap_or(*NUM_CPUS))
        .thread_name(move |i| format!("{}: {}", &prefix, i))
        .build()
        .unwrap()
}

impl<R: Read + io::Seek + Send + Sync + Clone> ZipArchive<R> {
    /// Extract a Zip archive into a directory, overwriting files if they
    /// already exist. Paths are sanitized with [`ZipFile::enclosed_name`].
    ///
    /// Extraction is not atomic; If an error is encountered, some of the files
    /// may be left on disk.
    pub fn extract_pipelined<P: AsRef<Path>>(&self, directory: P) -> ZipResult<()> {
        use rayon::prelude::*;

        use std::sync::mpsc;

        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;

        let (paths_tx, paths_rx) = mpsc::channel::<&Path>();
        let (dirs_task_tx, dirs_task_rx) = mpsc::channel::<ZipResult<()>>();
        let (stops_prior_tx, stops_prior_rx) = mpsc::sync_channel::<Vec<(&ZipFileData, &Path)>>(1);
        let (stops_tx, stops_rx) =
            mpsc::sync_channel::<(&ZipFileData, &Path, IntermediateFile)>(200);
        let (processed_tx, processed_rx) =
            mpsc::sync_channel::<(&ZipFileData, &Path, IntermediateFile)>(200);

        static TOP_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| build_thread_pool(Some(64), "TOP"));
        static STOPS_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| build_thread_pool(None, "stops"));
        static READER_POOL: Lazy<rayon::ThreadPool> =
            Lazy::new(|| build_thread_pool(None, "reader"));
        static WRITER_POOL: Lazy<rayon::ThreadPool> =
            Lazy::new(|| build_thread_pool(None, "writer"));
        static EXTRACTOR_POOL: Lazy<rayon::ThreadPool> =
            Lazy::new(|| build_thread_pool(None, "extractor"));
        static DIR_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| build_thread_pool(None, "dir"));

        let completed_paths = Arc::new(RwLock::new(CompletedPaths::new()));
        let completed_paths2 = Arc::clone(&completed_paths);

        let shared = &self.shared;
        /* eprintln!("here1"); */
        let reader = self.reader.clone();

        let dirs_task_tx2 = dirs_task_tx.clone();
        TOP_POOL.in_place_scope(move |s| {
            let directory = directory;
            let directory2 = directory.clone();

            let dirs_task_tx3 = dirs_task_tx2.clone();
            /* (1) Collect a plan of where we'll need to seek and read in the underlying reader. */
            s.spawn(move |_| {
                dirs_task_tx3
                    .send(STOPS_POOL.install(move || {
                        let entries: Vec<_> = shared
                            .files
                            .par_iter()
                            .map(|data| {
                                data.enclosed_name()
                                    .ok_or(ZipError::InvalidArchive("Invalid file path"))
                                    .map(|relative_path| (data, relative_path))
                            })
                            .collect::<Result<Vec<_>, ZipError>>()?;

                        let stops: Vec<_> = entries
                            .into_par_iter()
                            .inspect(move |(_, relative_path)| {
                                paths_tx.send(relative_path).expect("paths_rx hung up!");
                            })
                            .filter(|(_, relative_path)| {
                                !relative_path.to_string_lossy().ends_with('/')
                            })
                            .collect();

                        stops_prior_tx
                            .try_send(stops)
                            .expect("expected send to work without blocking");
                        Ok::<_, ZipError>(())
                    }))
                    .expect("dirs_task_rx hung up! -1")
            });

            let dirs_task_tx3 = dirs_task_tx2.clone();
            s.spawn(move |_| {
                dirs_task_tx3
                    .send(READER_POOL.install(move || {
                        let stops = stops_prior_rx.recv().expect("stops_prior_tx hung up!");

                        /* (2) Execute the seek plan by splitting up the reader's extent into N contiguous
                         *     chunks. */
                        let mut chunk_size = stops.len() / *NUM_CPUS;
                        if chunk_size == 0 {
                            chunk_size = stops.len();
                        }

                        /* eprintln!("here2"); */
                        stops
                            .par_chunks(chunk_size)
                            .map(|chunk| (chunk.to_vec(), reader.clone()))
                            .try_for_each(move |(chunk, mut reader)| {
                                for (data, relative_path) in chunk.into_iter() {
                                    /* eprintln!("%%%%%%%%%"); */
                                    /* dbg!(relative_path); */

                                    let mut reader = find_content(data, &mut reader)?;

                                    /* eprintln!("2: %%%%%%%%%"); */
                                    /* reader.seek(io::SeekFrom::Start(start))?; */
                                    /* reader.read_exact(buf)?; */

                                    /* eprintln!("buf.len() = {}", buf.len()); */
                                    /* eprintln!( */
                                    /*     "buf[..20] = {:?}", */
                                    /*     &buf[..20], */
                                    /*     /\* String::from_utf8_lossy(&buf[..20]), *\/ */
                                    /* ); */

                                    /* eprintln!("3: %%%%%%%%%"); */
                                    const SPOOL_THRESHOLD: usize = 2_000;
                                    let len = data.uncompressed_size as usize;
                                    let mut outfile = if len < SPOOL_THRESHOLD {
                                        IntermediateFile::immediate(len)
                                    } else {
                                        IntermediateFile::paging(len)?
                                    };
                                    /* eprintln!("4: %%%%%%%%%"); */
                                    io::copy(&mut reader, &mut outfile)?;
                                    /* eprintln!("5: %%%%%%%%%"); */
                                    outfile.rewind()?;

                                    /* eprintln!("@{}", &outfile); */

                                    match stops_tx.send((data, relative_path, outfile)) {
                                        Ok(()) => {
                                            /* eprintln!("DONE: %% {}", relative_path.display()); */
                                        }
                                        Err(mpsc::SendError((_, relative_path, _))) => {
                                            panic!(
                                                "stops_rx hung up! was: {}",
                                                relative_path.display(),
                                            );
                                        }
                                    }
                                }
                                Ok::<_, ZipError>(())
                            })?;
                        Ok(())
                    }))
                    .expect("dirs_task_rx hung up!0");
            });

            s.spawn(move |_| {
                /* (0) create dirs/??? */
                dirs_task_tx
                    .send(DIR_POOL.install(move || {
                        let completed_paths2 = Arc::clone(&completed_paths);
                        paths_rx
                            .into_iter()
                            .par_bridge()
                            .map(move |relative_path| {
                                completed_paths2
                                    .read()
                                    .unwrap()
                                    .new_containing_dirs_needed(relative_path)
                            })
                            .filter(|new_dirs| !new_dirs.is_empty())
                            .try_for_each(move |new_dirs| {
                                for d in new_dirs.iter() {
                                    let outpath = directory2.join(d);
                                    match fs::create_dir(outpath) {
                                        Ok(()) => (),
                                        Err(e) => {
                                            if e.kind() == io::ErrorKind::AlreadyExists {
                                                /* ignore */
                                            } else {
                                                return Err(e.into());
                                            }
                                        }
                                    }
                                }

                                completed_paths.write().unwrap().write_dirs(&new_dirs[..]);
                                Ok::<_, ZipError>(())
                            })
                    }))
                    .expect("dirs_task_rx hung up!1");
            });

            let dirs_task_tx3 = dirs_task_tx2.clone();
            s.spawn(move |_| {
                dirs_task_tx2
                    .send(WRITER_POOL.install(move || {
                        /* dbg!("wtf"); */
                        stops_rx.into_iter().par_bridge().try_for_each(
                            move |(data, relative_path, source_handle)| {
                                /* eprintln!("0: @@@@@@"); */
                                /* eprintln!( */
                                /*     "@: {}/{}/{}", */
                                /*     relative_path.display(), */
                                /*     data.compressed_size, */
                                /*     &source_handle, */
                                /* ); */

                                let mut decompress_reader =
                                    ZipEntry::from_data(data, source_handle);

                                /* eprintln!("1: @@@@@@@@"); */

                                const UNCOMPRESSED_SPOOL_THRESHOLD: usize = 100_000;
                                let len = data.uncompressed_size as usize;
                                let mut outfile = if len < UNCOMPRESSED_SPOOL_THRESHOLD {
                                    IntermediateFile::immediate(len)
                                } else {
                                    IntermediateFile::paging(len)?
                                };
                                /* NB: this may decompress, which may take a lot of cpu! */
                                io::copy(&mut decompress_reader, &mut outfile)?;
                                /* eprintln!("2: @@@@@@@@"); */
                                outfile.rewind()?;

                                /* decompress_reader.into_inner().remove_backing_file()?; */

                                /* eprintln!("+++++++++"); */

                                processed_tx
                                    .send((data, relative_path, outfile))
                                    .expect("processed_rx hung up!");

                                /* eprintln!("#########"); */

                                Ok::<_, ZipError>(())
                            },
                        )?;

                        /* eprintln!("huh???"); */

                        Ok::<_, ZipError>(())
                    }))
                    .expect("dirs_task_rx hung up!2");
            });

            s.spawn(move |_| {
                let directory = directory; /* Move. */
                /* (4) extract/??? */
                dirs_task_tx3
                    .send(EXTRACTOR_POOL.install(move || {
                        processed_rx.into_iter().par_bridge().try_for_each(
                            move |(data, relative_path, mut file)| {
                                let outpath = directory.join(relative_path);
                                /* dbg!(&outpath); */
                                let mut outfile = match fs::File::create(&outpath) {
                                    Ok(f) => f,
                                    Err(e) => {
                                        if e.kind() == io::ErrorKind::NotFound {
                                            /* Somehow, the containing dir didn't
                                             * exist. Let's make it ourself and
                                             * enter it into the registry. */
                                            let new_dirs = completed_paths2
                                                .read()
                                                .unwrap()
                                                .new_containing_dirs_needed(&relative_path);
                                            /* dbg!(&new_dirs); */

                                            for d in new_dirs.iter() {
                                                let outpath = directory.join(d);
                                                match fs::create_dir(outpath) {
                                                    Ok(()) => (),
                                                    Err(e) => {
                                                        if e.kind() == io::ErrorKind::AlreadyExists
                                                        {
                                                            /* ignore */
                                                        } else {
                                                            return Err(e.into());
                                                        }
                                                    }
                                                }
                                            }

                                            if !new_dirs.is_empty() {
                                                completed_paths2
                                                    .write()
                                                    .unwrap()
                                                    .write_dirs(&new_dirs[..]);
                                            }

                                            fs::File::create(&outpath)?
                                        } else {
                                            return Err(e.into());
                                        }
                                    }
                                };
                                /* eprintln!("&&&&&&&&&&"); */
                                io::copy(&mut file, &mut outfile)?;
                                file.remove_backing_file()?;
                                // Set permissions
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    if let Some(mode) = data.unix_mode() {
                                        outfile
                                            .set_permissions(fs::Permissions::from_mode(mode))?;
                                    }
                                }
                                Ok::<_, ZipError>(())
                            },
                        )
                    }))
                    .expect("dirs_task_rx hung up!3");
            });
            Ok::<_, ZipError>(())
        })?;
        for result in dirs_task_rx.into_iter() {
            result?;
        }
        Ok(())
    }
}

const fn unsupported_zip_error<T>(detail: &'static str) -> ZipResult<T> {
    Err(ZipError::UnsupportedArchive(detail))
}

/// Parse a central directory entry to collect the information for the file.
pub(crate) fn central_header_to_zip_file<R: Read + Seek>(
    reader: &mut R,
    archive_offset: u64,
) -> ZipResult<ZipFileData> {
    let central_header_start = reader.stream_position()?;

    // Parse central header
    let signature = reader.read_u32_le()?;
    if signature != spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE {
        Err(ZipError::InvalidArchive("Invalid Central Directory header"))
    } else {
        central_header_to_zip_file_inner(reader, archive_offset, central_header_start)
    }
}

/// Parse a central directory entry to collect the information for the file.
fn central_header_to_zip_file_inner<R: Read>(
    reader: &mut R,
    archive_offset: u64,
    central_header_start: u64,
) -> ZipResult<ZipFileData> {
    let version_made_by = reader.read_u16_le()?;
    let _version_to_extract = reader.read_u16_le()?;
    let flags = reader.read_u16_le()?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let using_data_descriptor = flags & (1 << 3) != 0;
    let compression_method = reader.read_u16_le()?;
    let last_mod_time = reader.read_u16_le()?;
    let last_mod_date = reader.read_u16_le()?;
    let crc32 = reader.read_u32_le()?;
    let compressed_size = reader.read_u32_le()?;
    let uncompressed_size = reader.read_u32_le()?;
    let file_name_length = reader.read_u16_le()? as usize;
    let extra_field_length = reader.read_u16_le()? as usize;
    let file_comment_length = reader.read_u16_le()? as usize;
    let _disk_number = reader.read_u16_le()?;
    let _internal_file_attributes = reader.read_u16_le()?;
    let external_file_attributes = reader.read_u32_le()?;
    let offset = reader.read_u32_le()? as u64;
    let mut file_name_raw = vec![0; file_name_length];
    reader.read_exact(&mut file_name_raw)?;
    let mut extra_field = vec![0; extra_field_length];
    reader.read_exact(&mut extra_field)?;
    let mut file_comment_raw = vec![0; file_comment_length];
    reader.read_exact(&mut file_comment_raw)?;

    let file_name: Box<str> = match is_utf8 {
        true => String::from_utf8_lossy(&file_name_raw).into(),
        false => file_name_raw.from_cp437().into(),
    };
    let file_comment: Box<str> = match is_utf8 {
        true => String::from_utf8_lossy(&file_comment_raw).into(),
        false => file_comment_raw.from_cp437().into(),
    };

    // Construct the result
    let mut result = ZipFileData {
        system: System::from((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        using_data_descriptor,
        compression_method: {
            #[allow(deprecated)]
            CompressionMethod::from_u16(compression_method)
        },
        compression_level: None,
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw: file_name_raw.into(),
        extra_field: Some(Arc::new(extra_field)),
        central_extra_field: None,
        file_comment,
        header_start: offset,
        extra_data_start: None,
        central_header_start,
        data_start: OnceLock::new(),
        external_attributes: external_file_attributes,
        large_file: false,
        aes_mode: None,
        aes_extra_data_start: 0,
        extra_fields: Vec::new(),
    };

    match parse_extra_field(&mut result) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    let aes_enabled = result.compression_method == CompressionMethod::AES;
    if aes_enabled && result.aes_mode.is_none() {
        return Err(ZipError::InvalidArchive(
            "AES encryption without AES extra data field",
        ));
    }

    // Account for shifted zip offsets.
    result.header_start = result
        .header_start
        .checked_add(archive_offset)
        .ok_or(ZipError::InvalidArchive("Archive header is too large"))?;

    Ok(result)
}

fn parse_extra_field(file: &mut ZipFileData) -> ZipResult<()> {
    let Some(extra_field) = &file.extra_field else {
        return Ok(());
    };
    let mut reader = io::Cursor::new(extra_field.as_ref());

    while (reader.position() as usize) < extra_field.len() {
        let kind = reader.read_u16_le()?;
        let len = reader.read_u16_le()?;
        let mut len_left = len as i64;
        match kind {
            // Zip64 extended information extra field
            0x0001 => {
                if file.uncompressed_size == spec::ZIP64_BYTES_THR {
                    file.large_file = true;
                    file.uncompressed_size = reader.read_u64_le()?;
                    len_left -= 8;
                }
                if file.compressed_size == spec::ZIP64_BYTES_THR {
                    file.large_file = true;
                    file.compressed_size = reader.read_u64_le()?;
                    len_left -= 8;
                }
                if file.header_start == spec::ZIP64_BYTES_THR {
                    file.header_start = reader.read_u64_le()?;
                    len_left -= 8;
                }
            }
            0x9901 => {
                // AES
                if len != 7 {
                    return Err(ZipError::UnsupportedArchive(
                        "AES extra data field has an unsupported length",
                    ));
                }
                let vendor_version = reader.read_u16_le()?;
                let vendor_id = reader.read_u16_le()?;
                let mut out = [0u8];
                reader.read_exact(&mut out)?;
                let aes_mode = out[0];
                #[allow(deprecated)]
                let compression_method = CompressionMethod::from_u16(reader.read_u16_le()?);

                if vendor_id != 0x4541 {
                    return Err(ZipError::InvalidArchive("Invalid AES vendor"));
                }
                let vendor_version = match vendor_version {
                    0x0001 => AesVendorVersion::Ae1,
                    0x0002 => AesVendorVersion::Ae2,
                    _ => return Err(ZipError::InvalidArchive("Invalid AES vendor version")),
                };
                match aes_mode {
                    0x01 => {
                        file.aes_mode = Some((AesMode::Aes128, vendor_version, compression_method))
                    }
                    0x02 => {
                        file.aes_mode = Some((AesMode::Aes192, vendor_version, compression_method))
                    }
                    0x03 => {
                        file.aes_mode = Some((AesMode::Aes256, vendor_version, compression_method))
                    }
                    _ => return Err(ZipError::InvalidArchive("Invalid AES encryption strength")),
                };
                file.compression_method = compression_method;
            }
            0x5455 => {
                // extended timestamp
                // https://libzip.org/specifications/extrafld.txt

                file.extra_fields.push(ExtraField::ExtendedTimestamp(
                    ExtendedTimestamp::try_from_reader(&mut reader, len)?,
                ));

                // the reader for ExtendedTimestamp consumes `len` bytes
                len_left = 0;
            }
            _ => {
                // Other fields are ignored
            }
        }

        // We could also check for < 0 to check for errors
        if len_left > 0 {
            reader.seek(io::SeekFrom::Current(len_left))?;
        }
    }
    Ok(())
}

/// Methods for retrieving information on zip files
impl<'a> ZipFile<'a> {
    fn get_reader(&mut self) -> ZipResult<&mut ZipFileReader<'a>> {
        if let ZipFileReader::NoReader = self.reader {
            let data = &self.data;
            let crypto_reader = self.crypto_reader.take().expect("Invalid reader state");
            self.reader = make_reader(data.compression_method, data.crc32, crypto_reader)?;
        }
        Ok(&mut self.reader)
    }

    pub(crate) fn get_raw_reader(&mut self) -> &mut dyn Read {
        if let ZipFileReader::NoReader = self.reader {
            let crypto_reader = self.crypto_reader.take().expect("Invalid reader state");
            self.reader = ZipFileReader::Raw(crypto_reader.into_inner())
        }
        &mut self.reader
    }

    /// Get the version of the file
    pub fn version_made_by(&self) -> (u8, u8) {
        (
            self.data.version_made_by / 10,
            self.data.version_made_by % 10,
        )
    }

    /// Get the name of the file
    ///
    /// # Warnings
    ///
    /// It is dangerous to use this name directly when extracting an archive.
    /// It may contain an absolute path (`/etc/shadow`), or break out of the
    /// current directory (`../runtime`). Carelessly writing to these paths
    /// allows an attacker to craft a ZIP archive that will overwrite critical
    /// files.
    ///
    /// You can use the [`ZipFile::enclosed_name`] method to validate the name
    /// as a safe path.
    pub fn name(&self) -> &str {
        &self.data.file_name
    }

    /// Get the name of the file, in the raw (internal) byte representation.
    ///
    /// The encoding of this data is currently undefined.
    pub fn name_raw(&self) -> &[u8] {
        &self.data.file_name_raw
    }

    /// Get the name of the file in a sanitized form. It truncates the name to the first NULL byte,
    /// removes a leading '/' and removes '..' parts.
    #[deprecated(
        since = "0.5.7",
        note = "by stripping `..`s from the path, the meaning of paths can change.
                `mangled_name` can be used if this behaviour is desirable"
    )]
    pub fn sanitized_name(&self) -> PathBuf {
        self.mangled_name()
    }

    /// Rewrite the path, ignoring any path components with special meaning.
    ///
    /// - Absolute paths are made relative
    /// - [`ParentDir`]s are ignored
    /// - Truncates the filename at a NULL byte
    ///
    /// This is appropriate if you need to be able to extract *something* from
    /// any archive, but will easily misrepresent trivial paths like
    /// `foo/../bar` as `foo/bar` (instead of `bar`). Because of this,
    /// [`ZipFile::enclosed_name`] is the better option in most scenarios.
    ///
    /// [`ParentDir`]: `Component::ParentDir`
    pub fn mangled_name(&self) -> PathBuf {
        self.data.file_name_sanitized()
    }

    /// Ensure the file path is safe to use as a [`Path`].
    ///
    /// - It can't contain NULL bytes
    /// - It can't resolve to a path outside the current directory
    ///   > `foo/../bar` is fine, `foo/../../bar` is not.
    /// - It can't be an absolute path
    ///
    /// This will read well-formed ZIP files correctly, and is resistant
    /// to path-based exploits. It is recommended over
    /// [`ZipFile::mangled_name`].
    pub fn enclosed_name(&self) -> Option<PathBuf> {
        self.data.enclosed_name()
    }

    /// Get the comment of the file
    pub fn comment(&self) -> &str {
        &self.data.file_comment
    }

    /// Get the compression method used to store the file
    pub fn compression(&self) -> CompressionMethod {
        self.data.compression_method
    }

    /// Get the size of the file, in bytes, in the archive
    pub fn compressed_size(&self) -> u64 {
        self.data.compressed_size
    }

    /// Get the size of the file, in bytes, when uncompressed
    pub fn size(&self) -> u64 {
        self.data.uncompressed_size
    }

    /// Get the time the file was last modified
    pub fn last_modified(&self) -> DateTime {
        self.data.last_modified_time
    }
    /// Returns whether the file is actually a directory
    pub fn is_dir(&self) -> bool {
        self.name()
            .chars()
            .next_back()
            .map_or(false, |c| c == '/' || c == '\\')
    }

    /// Returns whether the file is a regular file
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// Get unix mode for the file
    pub fn unix_mode(&self) -> Option<u32> {
        self.data.unix_mode()
    }

    /// Get the CRC32 hash of the original file
    pub fn crc32(&self) -> u32 {
        self.data.crc32
    }

    /// Get the extra data of the zip header for this file
    pub fn extra_data(&self) -> Option<&[u8]> {
        self.data.extra_field.as_ref().map(|v| v.deref().deref())
    }

    /// Get the starting offset of the data of the compressed file
    pub fn data_start(&self) -> u64 {
        *self.data.data_start.get().unwrap_or(&0)
    }

    /// Get the starting offset of the zip header for this file
    pub fn header_start(&self) -> u64 {
        self.data.header_start
    }
    /// Get the starting offset of the zip header in the central directory for this file
    pub fn central_header_start(&self) -> u64 {
        self.data.central_header_start
    }

    /// iterate through all extra fields
    pub fn extra_data_fields(&self) -> impl Iterator<Item = &ExtraField> {
        self.data.extra_fields.iter()
    }
}

impl<'a> Read for ZipFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.get_reader()?.read(buf)
    }
}

impl<'a> Drop for ZipFile<'a> {
    fn drop(&mut self) {
        // self.data is Owned, this reader is constructed by a streaming reader.
        // In this case, we want to exhaust the reader so that the next file is accessible.
        if let Cow::Owned(_) = self.data {
            // Get the inner `Take` reader so all decryption, decompression and CRC calculation is skipped.
            match &mut self.reader {
                ZipFileReader::NoReader => {
                    let innerreader = self.crypto_reader.take();
                    let _ = copy(
                        &mut innerreader.expect("Invalid reader state").into_inner(),
                        &mut sink(),
                    );
                }
                reader => {
                    let innerreader = std::mem::replace(reader, ZipFileReader::NoReader);
                    innerreader.drain();
                }
            };
        }
    }
}

/// Read ZipFile structures from a non-seekable reader.
///
/// This is an alternative method to read a zip file. If possible, use the ZipArchive functions
/// as some information will be missing when reading this manner.
///
/// Reads a file header from the start of the stream. Will return `Ok(Some(..))` if a file is
/// present at the start of the stream. Returns `Ok(None)` if the start of the central directory
/// is encountered. No more files should be read after this.
///
/// The Drop implementation of ZipFile ensures that the reader will be correctly positioned after
/// the structure is done.
///
/// Missing fields are:
/// * `comment`: set to an empty string
/// * `data_start`: set to 0
/// * `external_attributes`: `unix_mode()`: will return None
pub fn read_zipfile_from_stream<'a, R: Read>(reader: &'a mut R) -> ZipResult<Option<ZipFile<'_>>> {
    let signature = reader.read_u32_le()?;

    match signature {
        spec::LOCAL_FILE_HEADER_SIGNATURE => (),
        spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE => return Ok(None),
        _ => return Err(ZipError::InvalidArchive("Invalid local file header")),
    }

    let version_made_by = reader.read_u16_le()?;
    let flags = reader.read_u16_le()?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let using_data_descriptor = flags & (1 << 3) != 0;
    #[allow(deprecated)]
    let compression_method = CompressionMethod::from_u16(reader.read_u16_le()?);
    let last_mod_time = reader.read_u16_le()?;
    let last_mod_date = reader.read_u16_le()?;
    let crc32 = reader.read_u32_le()?;
    let compressed_size = reader.read_u32_le()?;
    let uncompressed_size = reader.read_u32_le()?;
    let file_name_length = reader.read_u16_le()? as usize;
    let extra_field_length = reader.read_u16_le()? as usize;

    let mut file_name_raw = vec![0; file_name_length];
    reader.read_exact(&mut file_name_raw)?;
    let mut extra_field = vec![0; extra_field_length];
    reader.read_exact(&mut extra_field)?;

    let file_name: Box<str> = match is_utf8 {
        true => String::from_utf8_lossy(&file_name_raw).into(),
        false => file_name_raw.clone().from_cp437().into(),
    };

    let mut result = ZipFileData {
        system: System::from((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        using_data_descriptor,
        compression_method,
        compression_level: None,
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw: file_name_raw.into(),
        extra_field: Some(Arc::new(extra_field)),
        central_extra_field: None,
        file_comment: String::with_capacity(0).into_boxed_str(), // file comment is only available in the central directory
        // header_start and data start are not available, but also don't matter, since seeking is
        // not available.
        header_start: 0,
        extra_data_start: None,
        data_start: OnceLock::new(),
        central_header_start: 0,
        // The external_attributes field is only available in the central directory.
        // We set this to zero, which should be valid as the docs state 'If input came
        // from standard input, this field is set to zero.'
        external_attributes: 0,
        large_file: false,
        aes_mode: None,
        aes_extra_data_start: 0,
        extra_fields: Vec::new(),
    };

    match parse_extra_field(&mut result) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    if encrypted {
        return unsupported_zip_error("Encrypted files are not supported");
    }
    if using_data_descriptor {
        return unsupported_zip_error("The file length is not available in the local header");
    }

    let limit_reader = (reader as &'a mut dyn Read).take(result.compressed_size);

    let result_crc32 = result.crc32;
    let result_compression_method = result.compression_method;
    let crypto_reader = make_crypto_reader(
        result_compression_method,
        result_crc32,
        result.last_modified_time,
        result.using_data_descriptor,
        limit_reader,
        None,
        None,
        #[cfg(feature = "aes-crypto")]
        result.compressed_size,
    )?;

    Ok(Some(ZipFile {
        data: Cow::Owned(result),
        crypto_reader: None,
        reader: make_reader(result_compression_method, result_crc32, crypto_reader)?,
    }))
}

#[cfg(test)]
mod test {
    use crate::ZipArchive;
    use std::io::Cursor;

    #[test]
    fn invalid_offset() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/invalid_offset.zip"));
        let reader = ZipArchive::new(Cursor::new(v));
        assert!(reader.is_err());
    }

    #[test]
    fn invalid_offset2() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/invalid_offset2.zip"));
        let reader = ZipArchive::new(Cursor::new(v));
        assert!(reader.is_err());
    }

    #[test]
    fn zip64_with_leading_junk() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/zip64_demo.zip"));
        let reader = ZipArchive::new(Cursor::new(v)).unwrap();
        assert_eq!(reader.len(), 1);
    }

    #[test]
    fn zip_contents() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader = ZipArchive::new(Cursor::new(v)).unwrap();
        assert_eq!(reader.comment(), b"");
        assert_eq!(reader.by_index(0).unwrap().central_header_start(), 77);
    }

    #[test]
    fn zip_read_streaming() {
        use super::read_zipfile_from_stream;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader = Cursor::new(v);
        loop {
            if read_zipfile_from_stream(&mut reader).unwrap().is_none() {
                break;
            }
        }
    }

    #[test]
    fn zip_clone() {
        use super::ZipArchive;
        use std::io::Read;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader1 = ZipArchive::new(Cursor::new(v)).unwrap();
        let mut reader2 = reader1.clone();

        let mut file1 = reader1.by_index(0).unwrap();
        let mut file2 = reader2.by_index(0).unwrap();

        let t = file1.last_modified();
        assert_eq!(
            (
                t.year(),
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            ),
            (1980, 1, 1, 0, 0, 0)
        );

        let mut buf1 = [0; 5];
        let mut buf2 = [0; 5];
        let mut buf3 = [0; 5];
        let mut buf4 = [0; 5];

        file1.read_exact(&mut buf1).unwrap();
        file2.read_exact(&mut buf2).unwrap();
        file1.read_exact(&mut buf3).unwrap();
        file2.read_exact(&mut buf4).unwrap();

        assert_eq!(buf1, buf2);
        assert_eq!(buf3, buf4);
        assert_ne!(buf1, buf3);
    }

    #[test]
    fn file_and_dir_predicates() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/files_and_dirs.zip"));
        let mut zip = ZipArchive::new(Cursor::new(v)).unwrap();

        for i in 0..zip.len() {
            let zip_file = zip.by_index(i).unwrap();
            let full_name = zip_file.enclosed_name().unwrap();
            let file_name = full_name.file_name().unwrap().to_str().unwrap();
            assert!(
                (file_name.starts_with("dir") && zip_file.is_dir())
                    || (file_name.starts_with("file") && zip_file.is_file())
            );
        }
    }

    #[test]
    fn zip64_magic_in_filenames() {
        let files = vec![
            include_bytes!("../tests/data/zip64_magic_in_filename_1.zip").to_vec(),
            include_bytes!("../tests/data/zip64_magic_in_filename_2.zip").to_vec(),
            include_bytes!("../tests/data/zip64_magic_in_filename_3.zip").to_vec(),
            include_bytes!("../tests/data/zip64_magic_in_filename_4.zip").to_vec(),
            include_bytes!("../tests/data/zip64_magic_in_filename_5.zip").to_vec(),
        ];
        // Although we don't allow adding files whose names contain the ZIP64 CDB-end or
        // CDB-end-locator signatures, we still read them when they aren't genuinely ambiguous.
        for file in files {
            ZipArchive::new(Cursor::new(file)).unwrap();
        }
    }

    /// test case to ensure we don't preemptively over allocate based on the
    /// declared number of files in the CDE of an invalid zip when the number of
    /// files declared is more than the alleged offset in the CDE
    #[test]
    fn invalid_cde_number_of_files_allocation_smaller_offset() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!(
            "../tests/data/invalid_cde_number_of_files_allocation_smaller_offset.zip"
        ));
        let reader = ZipArchive::new(Cursor::new(v));
        assert!(reader.is_err() || reader.unwrap().is_empty());
    }

    /// test case to ensure we don't preemptively over allocate based on the
    /// declared number of files in the CDE of an invalid zip when the number of
    /// files declared is less than the alleged offset in the CDE
    #[test]
    fn invalid_cde_number_of_files_allocation_greater_offset() {
        use super::ZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!(
            "../tests/data/invalid_cde_number_of_files_allocation_greater_offset.zip"
        ));
        let reader = ZipArchive::new(Cursor::new(v));
        assert!(reader.is_err());
    }

    #[cfg(feature = "deflate64")]
    #[test]
    fn deflate64_index_out_of_bounds() -> std::io::Result<()> {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!(
            "../tests/data/raw_deflate64_index_out_of_bounds.zip"
        ));
        let mut reader = ZipArchive::new(Cursor::new(v))?;
        std::io::copy(&mut reader.by_index(0)?, &mut std::io::sink()).expect_err("Invalid file");
        Ok(())
    }

    #[cfg(feature = "deflate64")]
    #[test]
    fn deflate64_not_enough_space() {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/deflate64_issue_25.zip"));
        ZipArchive::new(Cursor::new(v)).expect_err("Invalid file");
    }

    #[cfg(feature = "_deflate-any")]
    #[test]
    fn test_read_with_data_descriptor() {
        use std::io::Read;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/data_descriptor.zip"));
        let mut reader = ZipArchive::new(Cursor::new(v)).unwrap();
        let mut decompressed = [0u8; 16];
        let mut file = reader.by_index(0).unwrap();
        assert_eq!(file.read(&mut decompressed).unwrap(), 12);
    }
}
