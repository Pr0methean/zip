//! Types for reading ZIP archives

#[cfg(feature = "aes-crypto")]
use crate::aes::{AesReader, AesReaderValid};
use crate::compression::CompressionMethod;
use crate::cp437::FromCp437;
use crate::crc32::Crc32Reader;
use crate::extra_fields::{ExtendedTimestamp, ExtraField};
use crate::read::zip_archive::{Shared, SharedBuilder};
use crate::result::{ZipError, ZipResult};
use crate::spec::{self, FixedSizeBlock, Zip32CentralDirectoryEnd, ZIP64_ENTRY_THR};
use crate::types::{
    AesMode, AesVendorVersion, DateTime, System, ZipCentralEntryBlock, ZipFileData,
    ZipLocalEntryBlock,
};
use crate::zipcrypto::{ZipCryptoReader, ZipCryptoReaderValid, ZipCryptoValidator};
use indexmap::IndexMap;
use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::create_dir_all;
use std::io::{self, copy, prelude::*, sink, SeekFrom};
use std::mem;
use std::mem::size_of;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

#[cfg(feature = "deflate-flate2")]
use flate2::read::DeflateDecoder;

#[cfg(feature = "deflate64")]
use deflate64::Deflate64Decoder;

#[cfg(feature = "bzip2")]
use bzip2::read::BzDecoder;

#[cfg(feature = "zstd")]
use zstd::stream::read::Decoder as ZstdDecoder;

mod config;

pub use config::*;

/// Provides high level API for reading from a stream.
pub(crate) mod stream;

#[cfg(feature = "lzma")]
pub(crate) mod lzma;

#[cfg(feature = "xz")]
pub(crate) mod xz;

// Put the struct declaration in a private module to convince rustdoc to display ZipArchive nicely
pub(crate) mod zip_archive {
    use indexmap::IndexMap;
    use std::sync::Arc;

    /// Extract immutable data from `ZipArchive` to make it cheap to clone
    #[derive(Debug)]
    pub(crate) struct Shared {
        pub(crate) files: super::IndexMap<Box<str>, super::ZipFileData>,
        pub(super) offset: u64,
        pub(super) dir_start: u64,
        // This isn't yet used anywhere, but it is here for use cases in the future.
        #[allow(dead_code)]
        pub(super) config: super::Config,
    }

    #[derive(Debug)]
    pub(crate) struct SharedBuilder {
        pub(crate) files: Vec<super::ZipFileData>,
        pub(super) offset: u64,
        pub(super) dir_start: u64,
        // This isn't yet used anywhere, but it is here for use cases in the future.
        #[allow(dead_code)]
        pub(super) config: super::Config,
    }

    impl SharedBuilder {
        pub fn build(self) -> Shared {
            let mut index_map = IndexMap::with_capacity(self.files.len());
            self.files.into_iter().for_each(|file| {
                index_map.insert(file.file_name.clone(), file);
            });
            Shared {
                files: index_map,
                offset: self.offset,
                dir_start: self.dir_start,
                config: self.config,
            }
        }
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

#[cfg(feature = "aes-crypto")]
use crate::aes::PWD_VERIFY_LENGTH;
use crate::extra_fields::UnicodeExtraField;
#[cfg(feature = "lzma")]
use crate::read::lzma::LzmaDecoder;
#[cfg(feature = "xz")]
use crate::read::xz::XzDecoder;
use crate::result::ZipError::{InvalidArchive, InvalidPassword, UnsupportedArchive};
use crate::spec::is_dir;
use crate::types::ffi::S_IFLNK;
use crate::unstable::{path_to_string, LittleEndianReadExt};
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
    #[cfg(feature = "xz")]
    Xz(Crc32Reader<XzDecoder<CryptoReader<'a>>>),
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
            #[cfg(feature = "xz")]
            ZipFileReader::Xz(r) => r.read(buf),
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
            #[cfg(feature = "xz")]
            ZipFileReader::Xz(r) => r.into_inner().into_inner().into_inner(),
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
    // TODO: use .get_or_try_init() once stabilized to provide a closure returning a Result!
    let data_start = match data.data_start.get() {
        Some(data_start) => *data_start,
        None => find_data_start(data, reader)?,
    };

    reader.seek(io::SeekFrom::Start(data_start))?;
    Ok((reader as &mut dyn Read).take(data.compressed_size))
}

fn find_data_start(
    data: &ZipFileData,
    reader: &mut (impl Read + Seek + Sized),
) -> Result<u64, ZipError> {
    // Go to start of data.
    reader.seek(io::SeekFrom::Start(data.header_start))?;

    // Parse static-sized fields and check the magic value.
    let block = ZipLocalEntryBlock::parse(reader)?;

    // Calculate the end of the local header from the fields we just parsed.
    let variable_fields_len =
        // Each of these fields must be converted to u64 before adding, as the result may
        // easily overflow a u16.
        block.file_name_length as u64 + block.extra_field_length as u64;
    let data_start =
        data.header_start + mem::size_of::<ZipLocalEntryBlock>() as u64 + variable_fields_len;
    // Set the value so we don't have to read it again.
    match data.data_start.set(data_start) {
        Ok(()) => (),
        // If the value was already set in the meantime, ensure it matches (this is probably
        // unnecessary).
        Err(_) => {
            debug_assert_eq!(*data.data_start.get().unwrap(), data_start);
        }
    }
    Ok(data_start)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_crypto_reader<'a>(
    compression_method: CompressionMethod,
    crc32: u32,
    mut last_modified_time: Option<DateTime>,
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
            if !using_data_descriptor {
                last_modified_time = None;
            }
            let validator = if let Some(last_modified_time) = last_modified_time {
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
        #[cfg(feature = "xz")]
        CompressionMethod::Xz => {
            let reader = XzDecoder::new(reader);
            Ok(ZipFileReader::Xz(Crc32Reader::new(
                reader,
                crc32,
                ae2_encrypted,
            )))
        }
        _ => Err(UnsupportedArchive("Compression method not supported")),
    }
}

#[derive(Debug)]
pub(crate) struct CentralDirectoryInfo {
    pub(crate) archive_offset: u64,
    pub(crate) directory_start: u64,
    pub(crate) cde_position: u64,
    pub(crate) number_of_files: usize,
    pub(crate) disk_number: u32,
    pub(crate) disk_with_central_directory: u32,
    pub(crate) is_zip64: bool,
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
            None => central_start,
        };
        let shared = Arc::new(zip_archive::Shared {
            files,
            offset: initial_offset,
            dir_start: central_start,
            config: Config {
                archive_offset: ArchiveOffset::Known(initial_offset),
            },
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
            // f.central_header_start = 0;
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
        config: &Config,
        reader: &mut R,
        footer: &spec::Zip32CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<CentralDirectoryInfo> {
        let archive_offset = match config.archive_offset {
            ArchiveOffset::Known(n) => n,
            ArchiveOffset::FromCentralDirectory | ArchiveOffset::Detect => {
                // Some zip files have data prepended to them, resulting in the
                // offsets all being too small. Get the amount of error by comparing
                // the actual file position we found the CDE at with the offset
                // recorded in the CDE.
                let mut offset = cde_start_pos
                    .checked_sub(footer.central_directory_size as u64)
                    .and_then(|x| x.checked_sub(footer.central_directory_offset as u64))
                    .ok_or(ZipError::InvalidArchive(
                        "Invalid central directory size or offset",
                    ))?;

                if config.archive_offset == ArchiveOffset::Detect {
                    // Check whether the archive offset makes sense by peeking at the directory start. If it
                    // doesn't, fall back to using no archive offset. This supports zips with the central
                    // directory entries somewhere other than directly preceding the end of central directory.
                    reader.seek(io::SeekFrom::Start(
                        offset + footer.central_directory_offset as u64,
                    ))?;
                    let mut buf = [0; 4];
                    reader.read_exact(&mut buf)?;
                    if spec::Magic::from_le_bytes(buf)
                        != spec::Magic::CENTRAL_DIRECTORY_HEADER_SIGNATURE
                    {
                        offset = 0;
                    }
                }

                offset
            }
        };

        let directory_start = footer.central_directory_offset as u64 + archive_offset;
        let number_of_files = footer.number_of_files_on_this_disk as usize;
        Ok(CentralDirectoryInfo {
            archive_offset,
            directory_start,
            number_of_files,
            disk_number: footer.disk_number as u32,
            disk_with_central_directory: footer.disk_with_central_directory as u32,
            cde_position: cde_start_pos,
            is_zip64: false,
        })
    }

    const fn zip64_cde_len() -> usize {
        mem::size_of::<spec::Zip64CentralDirectoryEnd>()
            + mem::size_of::<spec::Zip64CentralDirectoryEndLocator>()
    }

    const fn order_lower_upper_bounds(a: u64, b: u64) -> (u64, u64) {
        if a > b {
            (b, a)
        } else {
            (a, b)
        }
    }

    fn get_directory_info_zip64(
        config: &Config,
        reader: &mut R,
        footer: &spec::Zip32CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<Vec<ZipResult<CentralDirectoryInfo>>> {
        // See if there's a ZIP64 footer. The ZIP64 locator if present will
        // have its signature 20 bytes in front of the standard footer. The
        // standard footer, in turn, is 22+N bytes large, where N is the
        // comment length. Therefore:
        /* TODO: compute this from constant sizes and offsets! */
        reader.seek(io::SeekFrom::End(
            -(20 + 22 + footer.zip_file_comment.len() as i64),
        ))?;
        let locator64 = spec::Zip64CentralDirectoryEndLocator::parse(reader)?;

        // We need to reassess `archive_offset`. We know where the ZIP64
        // central-directory-end structure *should* be, but unfortunately we
        // don't know how to precisely relate that location to our current
        // actual offset in the file, since there may be junk at its
        // beginning. Therefore we need to perform another search, as in
        // read::Zip32CentralDirectoryEnd::find_and_parse, except now we search
        // forward. There may be multiple results because of Zip64 central-directory signatures in
        // ZIP comment data.

        let search_upper_bound = cde_start_pos
            .checked_sub(Self::zip64_cde_len() as u64)
            .ok_or(ZipError::InvalidArchive(
                "File cannot contain ZIP64 central directory end",
            ))?;

        let (lower, upper) = Self::order_lower_upper_bounds(
            locator64.end_of_central_directory_offset,
            search_upper_bound,
        );

        let search_results = spec::Zip64CentralDirectoryEnd::find_and_parse(reader, lower, upper)?;
        let results: Vec<ZipResult<CentralDirectoryInfo>> =
            search_results.into_iter().map(|(footer64, archive_offset)| {
                let archive_offset = match config.archive_offset {
                    ArchiveOffset::Known(n) => n,
                    ArchiveOffset::FromCentralDirectory => archive_offset,
                    ArchiveOffset::Detect => {
                        archive_offset.checked_add(footer64.central_directory_offset)
                            .and_then(|start| {
                                // Check whether the archive offset makes sense by peeking at the directory start.
                                //
                                // If any errors occur or no header signature is found, fall back to no offset to see if that works.
                                reader.seek(io::SeekFrom::Start(start)).ok()?;
                                let mut buf = [0; 4];
                                reader.read_exact(&mut buf).ok()?;
                                if spec::Magic::from_le_bytes(buf) != spec::Magic::CENTRAL_DIRECTORY_HEADER_SIGNATURE {
                                    None
                                } else {
                                    Some(archive_offset)
                                }
                            })
                        .unwrap_or(0)
                    }
                };
                let directory_start = footer64
                    .central_directory_offset
                    .checked_add(archive_offset)
                    .ok_or(ZipError::InvalidArchive(
                        "Invalid central directory size or offset",
                    ))?;
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
                        cde_position: cde_start_pos,
                        is_zip64: true,
                    })
                }
            }).collect();
        Ok(results)
    }

    /// Get the directory start offset and number of files. This is done in a
    /// separate function to ease the control flow design.
    pub(crate) fn get_metadata(
        config: Config,
        reader: &mut R,
    ) -> ZipResult<(Zip32CentralDirectoryEnd, Shared)> {
        let mut invalid_errors_32 = Vec::new();
        let mut unsupported_errors_32 = Vec::new();
        let mut invalid_errors_64 = Vec::new();
        let mut unsupported_errors_64 = Vec::new();
        let mut ok_results = Vec::new();
        let cde_locations = spec::Zip32CentralDirectoryEnd::find_and_parse(reader)?;
        cde_locations
            .into_vec()
            .into_iter()
            .for_each(|(footer, cde_start_pos)| {
                let zip32_result =
                    Self::get_directory_info_zip32(&config, reader, &footer, cde_start_pos);
                Self::sort_result(
                    zip32_result,
                    &mut invalid_errors_32,
                    &mut unsupported_errors_32,
                    &mut ok_results,
                    &footer,
                );
                let mut inner_results = Vec::with_capacity(1);
                // Check if file has a zip64 footer
                let zip64_vec_result =
                    Self::get_directory_info_zip64(&config, reader, &footer, cde_start_pos);
                Self::sort_result(
                    zip64_vec_result,
                    &mut invalid_errors_64,
                    &mut unsupported_errors_64,
                    &mut inner_results,
                    &(),
                );
                inner_results.into_iter().for_each(|(_, results)| {
                    results.into_iter().for_each(|result| {
                        Self::sort_result(
                            result,
                            &mut invalid_errors_64,
                            &mut unsupported_errors_64,
                            &mut ok_results,
                            &footer,
                        );
                    });
                });
            });
        ok_results.sort_by_key(|(_, result)| {
            (
                u64::MAX - result.cde_position, // try the last one first
                !result.is_zip64,               // try ZIP64 first
            )
        });
        let mut best_result = None;
        for (footer, result) in ok_results {
            let mut inner_result = Vec::with_capacity(1);
            let is_zip64 = result.is_zip64;
            Self::sort_result(
                Self::read_central_header(result, config, reader),
                if is_zip64 {
                    &mut invalid_errors_64
                } else {
                    &mut invalid_errors_32
                },
                if is_zip64 {
                    &mut unsupported_errors_64
                } else {
                    &mut unsupported_errors_32
                },
                &mut inner_result,
                &(),
            );
            if let Some((_, shared)) = inner_result.into_iter().next() {
                if shared.files.len() == footer.number_of_files as usize
                    || (is_zip64 && footer.number_of_files == ZIP64_ENTRY_THR as u16)
                {
                    best_result = Some((footer, shared));
                    break;
                } else {
                    if is_zip64 {
                        &mut invalid_errors_64
                    } else {
                        &mut invalid_errors_32
                    }
                    .push(InvalidArchive("wrong number of files"))
                }
            }
        }
        let Some((footer, shared)) = best_result else {
            return Err(unsupported_errors_32
                .into_iter()
                .chain(unsupported_errors_64)
                .chain(invalid_errors_32)
                .chain(invalid_errors_64)
                .next()
                .unwrap());
        };
        reader.seek(io::SeekFrom::Start(shared.dir_start))?;
        Ok((Rc::try_unwrap(footer).unwrap(), shared.build()))
    }

    fn read_central_header(
        dir_info: CentralDirectoryInfo,
        config: Config,
        reader: &mut R,
    ) -> Result<SharedBuilder, ZipError> {
        // If the parsed number of files is greater than the offset then
        // something fishy is going on and we shouldn't trust number_of_files.
        let file_capacity = if dir_info.number_of_files > dir_info.directory_start as usize {
            0
        } else {
            dir_info.number_of_files
        };
        if dir_info.disk_number != dir_info.disk_with_central_directory {
            return unsupported_zip_error("Support for multi-disk files is not implemented");
        }
        let mut files = Vec::with_capacity(file_capacity);
        reader.seek(io::SeekFrom::Start(dir_info.directory_start))?;
        for _ in 0..dir_info.number_of_files {
            let file = central_header_to_zip_file(reader, dir_info.archive_offset)?;
            files.push(file);
        }
        Ok(SharedBuilder {
            files,
            offset: dir_info.archive_offset,
            dir_start: dir_info.directory_start,
            config,
        })
    }

    fn sort_result<T, U: Clone>(
        result: ZipResult<T>,
        invalid_errors: &mut Vec<ZipError>,
        unsupported_errors: &mut Vec<ZipError>,
        ok_results: &mut Vec<(U, T)>,
        footer: &U,
    ) {
        match result {
            Err(ZipError::UnsupportedArchive(e)) => {
                unsupported_errors.push(ZipError::UnsupportedArchive(e))
            }
            Err(e) => invalid_errors.push(e),
            Ok(o) => ok_results.push((footer.clone(), o)),
        }
    }

    /// Returns the verification value and salt for the AES encryption of the file
    ///
    /// It fails if the file number is invalid.
    ///
    /// # Returns
    ///
    /// - None if the file is not encrypted with AES
    #[cfg(feature = "aes-crypto")]
    pub fn get_aes_verification_key_and_salt(
        &mut self,
        file_number: usize,
    ) -> ZipResult<Option<AesInfo>> {
        let (_, data) = self
            .shared
            .files
            .get_index(file_number)
            .ok_or(ZipError::FileNotFound)?;

        let limit_reader = find_content(data, &mut self.reader)?;
        match data.aes_mode {
            None => Ok(None),
            Some((aes_mode, _, _)) => {
                let (verification_value, salt) =
                    AesReader::new(limit_reader, aes_mode, data.compressed_size)
                        .get_verification_value_and_salt()?;
                let aes_info = AesInfo {
                    aes_mode,
                    verification_value,
                    salt,
                };
                Ok(Some(aes_info))
            }
        }
    }

    /// Read a ZIP archive, collecting the files it contains.
    ///
    /// This uses the central directory record of the ZIP file, and ignores local file headers.
    ///
    /// A default [`Config`] is used.
    pub fn new(reader: R) -> ZipResult<ZipArchive<R>> {
        Self::with_config(Default::default(), reader)
    }

    /// Read a ZIP archive providing a read configuration, collecting the files it contains.
    ///
    /// This uses the central directory record of the ZIP file, and ignores local file headers.
    pub fn with_config(config: Config, mut reader: R) -> ZipResult<ZipArchive<R>> {
        reader.seek(SeekFrom::Start(0))?;
        if let Ok((footer, shared)) = Self::get_metadata(config, &mut reader) {
            return Ok(ZipArchive {
                reader,
                shared: shared.into(),
                comment: footer.zip_file_comment.into(),
            });
        }
        Err(InvalidArchive("No valid central directory found"))
    }

    /// Extract a Zip archive into a directory, overwriting files if they
    /// already exist. Paths are sanitized with [`ZipFile::enclosed_name`].
    ///
    /// Extraction is not atomic. If an error is encountered, some of the files
    /// may be left on disk. However, on Unix targets, no newly-created directories with part but
    /// not all of their contents extracted will be readable, writable or usable as process working
    /// directories by any non-root user except you.
    ///
    /// On Unix and Windows, symbolic links are extracted correctly. On other platforms such as
    /// WebAssembly, symbolic links aren't supported, so they're extracted as normal files
    /// containing the target path in UTF-8.
    pub fn extract<P: AsRef<Path>>(&mut self, directory: P) -> ZipResult<()> {
        use std::fs;
        #[cfg(unix)]
        let mut files_by_unix_mode = Vec::new();
        for i in 0..self.len() {
            let mut file = self.by_index(i)?;
            let filepath = file
                .enclosed_name()
                .ok_or(ZipError::InvalidArchive("Invalid file path"))?;

            let outpath = directory.as_ref().join(filepath);

            if file.is_dir() {
                Self::make_writable_dir_all(&outpath)?;
                continue;
            }
            let symlink_target = if file.is_symlink() && (cfg!(unix) || cfg!(windows)) {
                let mut target = Vec::with_capacity(file.size() as usize);
                file.read_exact(&mut target)?;
                Some(target)
            } else {
                None
            };
            drop(file);
            if let Some(p) = outpath.parent() {
                Self::make_writable_dir_all(p)?;
            }
            if let Some(target) = symlink_target {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStringExt;
                    let target = OsString::from_vec(target);
                    let target_path = directory.as_ref().join(target);
                    std::os::unix::fs::symlink(target_path, outpath.as_path())?;
                }
                #[cfg(windows)]
                {
                    let Ok(target) = String::from_utf8(target) else {
                        return Err(ZipError::InvalidArchive("Invalid UTF-8 as symlink target"));
                    };
                    let target = target.into_boxed_str();
                    let target_is_dir_from_archive =
                        self.shared.files.contains_key(&target) && is_dir(&target);
                    let target_path = directory.as_ref().join(OsString::from(target.to_string()));
                    let target_is_dir = if target_is_dir_from_archive {
                        true
                    } else if let Ok(meta) = std::fs::metadata(&target_path) {
                        meta.is_dir()
                    } else {
                        false
                    };
                    if target_is_dir {
                        std::os::windows::fs::symlink_dir(target_path, outpath.as_path())?;
                    } else {
                        std::os::windows::fs::symlink_file(target_path, outpath.as_path())?;
                    }
                }
                continue;
            }
            let mut file = self.by_index(i)?;
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
            #[cfg(unix)]
            {
                // Check for real permissions, which we'll set in a second pass
                if let Some(mode) = file.unix_mode() {
                    files_by_unix_mode.push((outpath.clone(), mode));
                }
            }
        }
        #[cfg(unix)]
        {
            use std::cmp::Reverse;
            use std::os::unix::fs::PermissionsExt;

            if files_by_unix_mode.len() > 1 {
                // Ensure we update children's permissions before making a parent unwritable
                files_by_unix_mode.sort_by_key(|(path, _)| Reverse(path.clone()));
            }
            for (path, mode) in files_by_unix_mode.into_iter() {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            }
        }
        Ok(())
    }

    fn make_writable_dir_all<T: AsRef<Path>>(outpath: T) -> Result<(), ZipError> {
        create_dir_all(outpath.as_ref())?;
        #[cfg(unix)]
        {
            // Dirs must be writable until all normal files are extracted
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                outpath.as_ref(),
                std::fs::Permissions::from_mode(
                    0o700 | std::fs::metadata(outpath.as_ref())?.permissions().mode(),
                ),
            )?;
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

/// Holds the AES information of a file in the zip archive
#[derive(Debug)]
#[cfg(feature = "aes-crypto")]
pub struct AesInfo {
    /// The AES encryption mode
    pub aes_mode: AesMode,
    /// The verification key
    pub verification_value: [u8; PWD_VERIFY_LENGTH],
    /// The salt
    pub salt: Vec<u8>,
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
    let block = ZipCentralEntryBlock::parse(reader)?;
    let file =
        central_header_to_zip_file_inner(reader, archive_offset, central_header_start, block)?;
    let central_header_end = reader.stream_position()?;
    let data_start = find_data_start(&file, reader)?;
    if data_start > central_header_start {
        return Err(InvalidArchive(
            "A file can't start after its central-directory header",
        ));
    }
    file.data_start.get_or_init(|| data_start);
    reader.seek(SeekFrom::Start(central_header_end))?;
    Ok(file)
}

#[inline]
fn read_variable_length_byte_field<R: Read>(reader: &mut R, len: usize) -> io::Result<Box<[u8]>> {
    let mut data = vec![0; len].into_boxed_slice();
    reader.read_exact(&mut data)?;
    Ok(data)
}

/// Parse a central directory entry to collect the information for the file.
fn central_header_to_zip_file_inner<R: Read>(
    reader: &mut R,
    archive_offset: u64,
    central_header_start: u64,
    block: ZipCentralEntryBlock,
) -> ZipResult<ZipFileData> {
    let ZipCentralEntryBlock {
        // magic,
        version_made_by,
        // version_to_extract,
        flags,
        compression_method,
        last_mod_time,
        last_mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        file_name_length,
        extra_field_length,
        file_comment_length,
        // disk_number,
        // internal_file_attributes,
        external_file_attributes,
        offset,
        ..
    } = block;

    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let using_data_descriptor = flags & (1 << 3) != 0;

    let file_name_raw = read_variable_length_byte_field(reader, file_name_length as usize)?;
    let extra_field = read_variable_length_byte_field(reader, extra_field_length as usize)?;
    let file_comment_raw = read_variable_length_byte_field(reader, file_comment_length as usize)?;
    let file_name: Box<str> = match is_utf8 {
        true => String::from_utf8_lossy(&file_name_raw).into(),
        false => file_name_raw.clone().from_cp437(),
    };
    let file_comment: Box<str> = match is_utf8 {
        true => String::from_utf8_lossy(&file_comment_raw).into(),
        false => file_comment_raw.from_cp437(),
    };

    // Construct the result
    let mut result = ZipFileData {
        system: System::from((version_made_by >> 8) as u8),
        /* NB: this strips the top 8 bits! */
        version_made_by: version_made_by as u8,
        encrypted,
        using_data_descriptor,
        is_utf8,
        compression_method: CompressionMethod::parse_from_u16(compression_method),
        compression_level: None,
        last_modified_time: DateTime::try_from_msdos(last_mod_date, last_mod_time).ok(),
        crc32,
        compressed_size: compressed_size.into(),
        uncompressed_size: uncompressed_size.into(),
        file_name,
        file_name_raw,
        extra_field: Some(Arc::new(extra_field.to_vec())),
        central_extra_field: None,
        file_comment,
        header_start: offset.into(),
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
        Ok(stripped_extra_field) => {
            result.extra_field = stripped_extra_field;
        }
        Err(ZipError::Io(..)) => {}
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

pub(crate) fn parse_extra_field(file: &mut ZipFileData) -> ZipResult<Option<Arc<Vec<u8>>>> {
    let Some(ref extra_field) = file.extra_field else {
        return Ok(None);
    };
    let extra_field = extra_field.clone();
    let mut processed_extra_field = extra_field.clone();
    let len = extra_field.len();
    let mut reader = io::Cursor::new(&**extra_field);

    /* TODO: codify this structure into Zip64ExtraFieldBlock fields! */
    let mut position = reader.position() as usize;
    while (position) < len {
        let old_position = position;
        let remove = parse_single_extra_field(file, &mut reader, position as u64, false)?;
        position = reader.position() as usize;
        if remove {
            let remaining = len - (position - old_position);
            if remaining == 0 {
                return Ok(None);
            }
            let mut new_extra_field = Vec::with_capacity(remaining);
            new_extra_field.extend_from_slice(&extra_field[0..old_position]);
            new_extra_field.extend_from_slice(&extra_field[position..]);
            processed_extra_field = Arc::new(new_extra_field);
        }
    }
    Ok(Some(processed_extra_field))
}

pub(crate) fn parse_single_extra_field<R: Read>(
    file: &mut ZipFileData,
    reader: &mut R,
    bytes_already_read: u64,
    disallow_zip64: bool,
) -> ZipResult<bool> {
    let kind = reader.read_u16_le()?;
    let len = reader.read_u16_le()?;
    match kind {
        // Zip64 extended information extra field
        0x0001 => {
            if disallow_zip64 {
                return Err(InvalidArchive(
                    "Can't write a custom field using the ZIP64 ID",
                ));
            }
            let mut consumed_len = 0;
            if len >= 24 || file.uncompressed_size == spec::ZIP64_BYTES_THR {
                file.large_file = true;
                file.uncompressed_size = reader.read_u64_le()?;
                consumed_len += size_of::<u64>();
            }
            if len >= 24 || file.compressed_size == spec::ZIP64_BYTES_THR {
                file.large_file = true;
                file.compressed_size = reader.read_u64_le()?;
                consumed_len += size_of::<u64>();
            }
            if len >= 24 || file.header_start == spec::ZIP64_BYTES_THR {
                file.header_start = reader.read_u64_le()?;
                consumed_len += size_of::<u64>();
            }
            let Some(leftover_len) = (len as usize).checked_sub(consumed_len) else {
                return Err(InvalidArchive("ZIP64 extra-data field is the wrong length"));
            };
            reader.read_exact(&mut vec![0u8; leftover_len])?;
            return Ok(true);
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
            let compression_method = CompressionMethod::parse_from_u16(reader.read_u16_le()?);

            if vendor_id != 0x4541 {
                return Err(ZipError::InvalidArchive("Invalid AES vendor"));
            }
            let vendor_version = match vendor_version {
                0x0001 => AesVendorVersion::Ae1,
                0x0002 => AesVendorVersion::Ae2,
                _ => return Err(ZipError::InvalidArchive("Invalid AES vendor version")),
            };
            match aes_mode {
                0x01 => file.aes_mode = Some((AesMode::Aes128, vendor_version, compression_method)),
                0x02 => file.aes_mode = Some((AesMode::Aes192, vendor_version, compression_method)),
                0x03 => file.aes_mode = Some((AesMode::Aes256, vendor_version, compression_method)),
                _ => return Err(ZipError::InvalidArchive("Invalid AES encryption strength")),
            };
            file.compression_method = compression_method;
            file.aes_extra_data_start = bytes_already_read;
        }
        0x5455 => {
            // extended timestamp
            // https://libzip.org/specifications/extrafld.txt

            file.extra_fields.push(ExtraField::ExtendedTimestamp(
                ExtendedTimestamp::try_from_reader(reader, len)?,
            ));
        }
        0x6375 => {
            // Info-ZIP Unicode Comment Extra Field
            // APPNOTE 4.6.8 and https://libzip.org/specifications/extrafld.txt
            file.file_comment = String::from_utf8(
                UnicodeExtraField::try_from_reader(reader, len)?
                    .unwrap_valid(file.file_comment.as_bytes())?
                    .into_vec(),
            )?
            .into();
        }
        0x7075 => {
            // Info-ZIP Unicode Path Extra Field
            // APPNOTE 4.6.9 and https://libzip.org/specifications/extrafld.txt
            file.file_name_raw = UnicodeExtraField::try_from_reader(reader, len)?
                .unwrap_valid(&file.file_name_raw)?;
            file.file_name =
                String::from_utf8(file.file_name_raw.clone().into_vec())?.into_boxed_str();
            file.is_utf8 = true;
        }
        _ => {
            reader.read_exact(&mut vec![0u8; len as usize])?;
            // Other fields are ignored
        }
    }
    Ok(false)
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
    pub fn last_modified(&self) -> Option<DateTime> {
        self.data.last_modified_time
    }
    /// Returns whether the file is actually a directory
    pub fn is_dir(&self) -> bool {
        is_dir(self.name())
    }

    /// Returns whether the file is actually a symbolic link
    pub fn is_symlink(&self) -> bool {
        self.unix_mode()
            .is_some_and(|mode| mode & S_IFLNK == S_IFLNK)
    }

    /// Returns whether the file is a normal file (i.e. not a directory or symlink)
    pub fn is_file(&self) -> bool {
        !self.is_dir() && !self.is_symlink()
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
        *self.data.data_start.get().unwrap()
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
    // We can't use the typical ::parse() method, as we follow separate code paths depending on the
    // "magic" value (since the magic value will be from the central directory header if we've
    // finished iterating over all the actual files).
    /* TODO: smallvec? */
    let mut block = [0u8; mem::size_of::<ZipLocalEntryBlock>()];
    reader.read_exact(&mut block)?;
    let block: Box<[u8]> = block.into();

    let signature = spec::Magic::from_first_le_bytes(&block);

    match signature {
        spec::Magic::LOCAL_FILE_HEADER_SIGNATURE => (),
        spec::Magic::CENTRAL_DIRECTORY_HEADER_SIGNATURE => return Ok(None),
        _ => return Err(ZipLocalEntryBlock::WRONG_MAGIC_ERROR),
    }

    let block = ZipLocalEntryBlock::interpret(&block)?;

    let mut result = ZipFileData::from_local_block(block, reader)?;

    match parse_extra_field(&mut result) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
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
    use crate::result::ZipResult;
    use crate::write::SimpleFileOptions;
    use crate::CompressionMethod::Stored;
    use crate::{ZipArchive, ZipWriter};
    use std::io::{Cursor, Read, Write};
    use tempdir::TempDir;

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

        let t = file1.last_modified().unwrap();
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

    #[test]
    fn test_is_symlink() -> std::io::Result<()> {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/symlink.zip"));
        let mut reader = ZipArchive::new(Cursor::new(v)).unwrap();
        assert!(reader.by_index(0).unwrap().is_symlink());
        let tempdir = TempDir::new("test_is_symlink")?;
        reader.extract(&tempdir).unwrap();
        assert!(tempdir.path().join("bar").is_symlink());
        Ok(())
    }

    #[test]
    #[cfg(feature = "_deflate-any")]
    fn test_utf8_extra_field() {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/chinese.zip"));
        let mut reader = ZipArchive::new(Cursor::new(v)).unwrap();
        reader.by_name("七个房间.txt").unwrap();
    }

    #[test]
    fn test_utf8() {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/linux-7z.zip"));
        let mut reader = ZipArchive::new(Cursor::new(v)).unwrap();
        reader.by_name("你好.txt").unwrap();
    }

    #[test]
    fn test_utf8_2() {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/windows-7zip.zip"));
        let mut reader = ZipArchive::new(Cursor::new(v)).unwrap();
        reader.by_name("你好.txt").unwrap();
    }

    #[test]
    fn test_64k_files() -> ZipResult<()> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions {
            compression_method: Stored,
            ..Default::default()
        };
        for i in 0..=u16::MAX {
            let file_name = format!("{i}.txt");
            writer.start_file(&*file_name, options)?;
            writer.write_all(i.to_string().as_bytes())?;
        }

        let mut reader = ZipArchive::new(writer.finish()?)?;
        for i in 0..=u16::MAX {
            let expected_name = format!("{i}.txt");
            let expected_contents = i.to_string();
            let expected_contents = expected_contents.as_bytes();
            let mut file = reader.by_name(&expected_name)?;
            let mut contents = Vec::with_capacity(expected_contents.len());
            file.read_to_end(&mut contents)?;
            assert_eq!(contents, expected_contents);
            drop(file);
            contents.clear();
            let mut file = reader.by_index(i as usize)?;
            file.read_to_end(&mut contents)?;
            assert_eq!(contents, expected_contents);
        }
        Ok(())
    }
}
