#![allow(missing_docs, dead_code)]
use crate::result::{ZipError, ZipResult};
use crate::unstable::{LittleEndianReadExt, LittleEndianWriteExt};
use core::mem::size_of_val;
use std::borrow::Cow;
use std::io;
use std::io::prelude::*;
use std::path::{Component, Path, MAIN_SEPARATOR};

pub const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;
pub const CENTRAL_DIRECTORY_HEADER_SIGNATURE: u32 = 0x02014b50;
pub(crate) const CENTRAL_DIRECTORY_END_SIGNATURE: u32 = 0x06054b50;
pub const ZIP64_CENTRAL_DIRECTORY_END_SIGNATURE: u32 = 0x06064b50;
pub(crate) const ZIP64_CENTRAL_DIRECTORY_END_LOCATOR_SIGNATURE: u32 = 0x07064b50;
pub const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x08074b50;

pub const ZIP64_BYTES_THR: u64 = u32::MAX as u64;
pub const ZIP64_ENTRY_THR: usize = u16::MAX as usize;

#[derive(Clone, Debug, PartialEq)]
pub struct CentralDirectoryEnd {
    pub disk_number: u16,
    pub disk_with_central_directory: u16,
    pub number_of_files_on_this_disk: u16,
    pub number_of_files: u16,
    pub central_directory_size: u32,
    pub central_directory_offset: u32,
    pub zip_file_comment: Box<[u8]>,
}

impl CentralDirectoryEnd {
    pub fn len(&self) -> usize {
        22 + self.zip_file_comment.len()
    }

    pub fn parse<T: Read>(reader: &mut T) -> ZipResult<CentralDirectoryEnd> {
        let magic = reader.read_u32_le()?;
        if magic != CENTRAL_DIRECTORY_END_SIGNATURE {
            return Err(ZipError::InvalidArchive("Invalid digital signature header"));
        }
        let disk_number = reader.read_u16_le()?;
        let disk_with_central_directory = reader.read_u16_le()?;
        let number_of_files_on_this_disk = reader.read_u16_le()?;
        let number_of_files = reader.read_u16_le()?;
        let central_directory_size = reader.read_u32_le()?;
        let central_directory_offset = reader.read_u32_le()?;
        let zip_file_comment_length = reader.read_u16_le()? as usize;
        let mut zip_file_comment = vec![0; zip_file_comment_length].into_boxed_slice();
        reader.read_exact(&mut zip_file_comment)?;

        Ok(CentralDirectoryEnd {
            disk_number,
            disk_with_central_directory,
            number_of_files_on_this_disk,
            number_of_files,
            central_directory_size,
            central_directory_offset,
            zip_file_comment,
        })
    }

    pub fn find_and_parse<T: Read + Seek>(reader: &mut T) -> ZipResult<(CentralDirectoryEnd, u64)> {
        const HEADER_SIZE: u64 = 22;
        const MAX_HEADER_AND_COMMENT_SIZE: u64 = 66000;
        const BYTES_BETWEEN_MAGIC_AND_COMMENT_SIZE: u64 = HEADER_SIZE - 6;
        let file_length = reader.seek(io::SeekFrom::End(0))?;

        let search_upper_bound = file_length.saturating_sub(MAX_HEADER_AND_COMMENT_SIZE);

        if file_length < HEADER_SIZE {
            return Err(ZipError::InvalidArchive("Invalid zip header"));
        }

        let mut pos = file_length - HEADER_SIZE;
        while pos >= search_upper_bound {
            let mut have_signature = false;
            reader.seek(io::SeekFrom::Start(pos))?;
            if reader.read_u32_le()? == CENTRAL_DIRECTORY_END_SIGNATURE {
                have_signature = true;
                reader.seek(io::SeekFrom::Current(
                    BYTES_BETWEEN_MAGIC_AND_COMMENT_SIZE as i64,
                ))?;
                let cde_start_pos = reader.seek(io::SeekFrom::Start(pos))?;
                if let Ok(end_header) = CentralDirectoryEnd::parse(reader) {
                    return Ok((end_header, cde_start_pos));
                }
            }
            pos = match pos.checked_sub(if have_signature {
                size_of_val(&CENTRAL_DIRECTORY_END_SIGNATURE) as u64
            } else {
                1
            }) {
                Some(p) => p,
                None => break,
            };
        }
        Err(ZipError::InvalidArchive(
            "Could not find central directory end",
        ))
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> ZipResult<()> {
        writer.write_u32_le(CENTRAL_DIRECTORY_END_SIGNATURE)?;
        writer.write_u16_le(self.disk_number)?;
        writer.write_u16_le(self.disk_with_central_directory)?;
        writer.write_u16_le(self.number_of_files_on_this_disk)?;
        writer.write_u16_le(self.number_of_files)?;
        writer.write_u32_le(self.central_directory_size)?;
        writer.write_u32_le(self.central_directory_offset)?;
        writer.write_u16_le(self.zip_file_comment.len() as u16)?;
        writer.write_all(&self.zip_file_comment)?;
        Ok(())
    }
}

pub struct Zip64CentralDirectoryEndLocator {
    pub disk_with_central_directory: u32,
    pub end_of_central_directory_offset: u64,
    pub number_of_disks: u32,
}

impl Zip64CentralDirectoryEndLocator {
    pub fn parse<T: Read>(reader: &mut T) -> ZipResult<Zip64CentralDirectoryEndLocator> {
        let magic = reader.read_u32_le()?;
        if magic != ZIP64_CENTRAL_DIRECTORY_END_LOCATOR_SIGNATURE {
            return Err(ZipError::InvalidArchive(
                "Invalid zip64 locator digital signature header",
            ));
        }
        let disk_with_central_directory = reader.read_u32_le()?;
        let end_of_central_directory_offset = reader.read_u64_le()?;
        let number_of_disks = reader.read_u32_le()?;

        Ok(Zip64CentralDirectoryEndLocator {
            disk_with_central_directory,
            end_of_central_directory_offset,
            number_of_disks,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> ZipResult<()> {
        writer.write_u32_le(ZIP64_CENTRAL_DIRECTORY_END_LOCATOR_SIGNATURE)?;
        writer.write_u32_le(self.disk_with_central_directory)?;
        writer.write_u64_le(self.end_of_central_directory_offset)?;
        writer.write_u32_le(self.number_of_disks)?;
        Ok(())
    }
}

pub struct Zip64CentralDirectoryEnd {
    pub version_made_by: u16,
    pub version_needed_to_extract: u16,
    pub disk_number: u32,
    pub disk_with_central_directory: u32,
    pub number_of_files_on_this_disk: u64,
    pub number_of_files: u64,
    pub central_directory_size: u64,
    pub central_directory_offset: u64,
    //pub extensible_data_sector: Vec<u8>, <-- We don't do anything with this at the moment.
}

impl Zip64CentralDirectoryEnd {
    pub fn find_and_parse<T: Read + Seek>(
        reader: &mut T,
        nominal_offset: u64,
        search_upper_bound: u64,
    ) -> ZipResult<Vec<(Zip64CentralDirectoryEnd, u64)>> {
        let mut results = Vec::new();
        let mut pos = search_upper_bound;

        while pos >= nominal_offset {
            let mut have_signature = false;
            reader.seek(io::SeekFrom::Start(pos))?;
            if reader.read_u32_le()? == ZIP64_CENTRAL_DIRECTORY_END_SIGNATURE {
                have_signature = true;
                let archive_offset = pos - nominal_offset;

                let _record_size = reader.read_u64_le()?;
                // We would use this value if we did anything with the "zip64 extensible data sector".

                let version_made_by = reader.read_u16_le()?;
                let version_needed_to_extract = reader.read_u16_le()?;
                let disk_number = reader.read_u32_le()?;
                let disk_with_central_directory = reader.read_u32_le()?;
                let number_of_files_on_this_disk = reader.read_u64_le()?;
                let number_of_files = reader.read_u64_le()?;
                let central_directory_size = reader.read_u64_le()?;
                let central_directory_offset = reader.read_u64_le()?;

                results.push((
                    Zip64CentralDirectoryEnd {
                        version_made_by,
                        version_needed_to_extract,
                        disk_number,
                        disk_with_central_directory,
                        number_of_files_on_this_disk,
                        number_of_files,
                        central_directory_size,
                        central_directory_offset,
                    },
                    archive_offset,
                ));
            }
            pos = match pos.checked_sub(if have_signature {
                size_of_val(&ZIP64_CENTRAL_DIRECTORY_END_SIGNATURE) as u64
            } else {
                1
            }) {
                None => break,
                Some(p) => p,
            }
        }
        if results.is_empty() {
            Err(ZipError::InvalidArchive(
                "Could not find ZIP64 central directory end",
            ))
        } else {
            Ok(results)
        }
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> ZipResult<()> {
        writer.write_u32_le(ZIP64_CENTRAL_DIRECTORY_END_SIGNATURE)?;
        writer.write_u64_le(44)?; // record size
        writer.write_u16_le(self.version_made_by)?;
        writer.write_u16_le(self.version_needed_to_extract)?;
        writer.write_u32_le(self.disk_number)?;
        writer.write_u32_le(self.disk_with_central_directory)?;
        writer.write_u64_le(self.number_of_files_on_this_disk)?;
        writer.write_u64_le(self.number_of_files)?;
        writer.write_u64_le(self.central_directory_size)?;
        writer.write_u64_le(self.central_directory_offset)?;
        Ok(())
    }
}

pub(crate) fn is_dir(filename: &str) -> bool {
    filename
        .chars()
        .next_back()
        .map_or(false, |c| c == '/' || c == '\\')
}

/// Converts a path to the ZIP format (forward-slash-delimited and normalized).
pub(crate) fn path_to_string<T: AsRef<Path>>(path: T) -> Box<str> {
    let mut maybe_original = None;
    if let Some(original) = path.as_ref().to_str() {
        if (MAIN_SEPARATOR == '/' || !original[1..].contains(MAIN_SEPARATOR))
            && !original.ends_with('.')
            && !original.starts_with(['.', MAIN_SEPARATOR])
            && !original.starts_with(['.', '.', MAIN_SEPARATOR])
            && !original.contains([MAIN_SEPARATOR, MAIN_SEPARATOR])
            && !original.contains([MAIN_SEPARATOR, '.', MAIN_SEPARATOR])
            && !original.contains([MAIN_SEPARATOR, '.', '.', MAIN_SEPARATOR])
        {
            if original.starts_with(MAIN_SEPARATOR) {
                maybe_original = Some(&original[1..]);
            } else {
                maybe_original = Some(original);
            }
        }
    }
    let mut recreate = maybe_original.is_none();
    let mut normalized_components = Vec::new();

    for component in path.as_ref().components() {
        match component {
            Component::Normal(os_str) => match os_str.to_str() {
                Some(valid_str) => normalized_components.push(Cow::Borrowed(valid_str)),
                None => {
                    recreate = true;
                    normalized_components.push(os_str.to_string_lossy());
                }
            },
            Component::ParentDir => {
                recreate = true;
                normalized_components.pop();
            }
            _ => {
                recreate = true;
            }
        }
    }
    if recreate {
        normalized_components.join("/").into()
    } else {
        maybe_original.unwrap().into()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct GeneralPurposeBitFlags(pub u16);

impl GeneralPurposeBitFlags {
    #[inline]
    pub fn encrypted(&self) -> bool {
        self.0 & 1 == 1
    }

    #[inline]
    pub fn is_utf8(&self) -> bool {
        self.0 & (1 << 11) != 0
    }

    #[inline]
    pub fn using_data_descriptor(&self) -> bool {
        self.0 & (1 << 3) != 0
    }

    #[inline]
    pub fn set_using_data_descriptor(&mut self, b: bool) {
        self.0 &= !(1 << 3);
        if b {
            self.0 |= 1 << 3;
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CentralDirectoryHeader {
    pub version_made_by: u16,
    pub version_to_extract: u16,
    pub flags: GeneralPurposeBitFlags,
    pub compression_method: u16,
    pub last_mod_time: u16,
    pub last_mod_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub disk_number: u16,
    pub internal_file_attributes: u16,
    pub external_file_attributes: u32,
    pub offset: u32,
    pub file_name_raw: Vec<u8>,
    pub extra_field: Vec<u8>,
    pub file_comment_raw: Vec<u8>,
}

impl CentralDirectoryHeader {
    pub fn len(&self) -> usize {
        46 + self.file_name_raw.len() + self.extra_field.len() + self.file_comment_raw.len()
    }
    pub fn parse<R: Read>(reader: &mut R) -> ZipResult<CentralDirectoryHeader> {
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != CENTRAL_DIRECTORY_HEADER_SIGNATURE {
            return Err(ZipError::InvalidArchive("Invalid Central Directory header"));
        }

        let version_made_by = reader.read_u16::<LittleEndian>()?;
        let version_to_extract = reader.read_u16::<LittleEndian>()?;
        let flags = reader.read_u16::<LittleEndian>()?;
        let compression_method = reader.read_u16::<LittleEndian>()?;
        let last_mod_time = reader.read_u16::<LittleEndian>()?;
        let last_mod_date = reader.read_u16::<LittleEndian>()?;
        let crc32 = reader.read_u32::<LittleEndian>()?;
        let compressed_size = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;
        let file_name_length = reader.read_u16::<LittleEndian>()?;
        let extra_field_length = reader.read_u16::<LittleEndian>()?;
        let file_comment_length = reader.read_u16::<LittleEndian>()?;
        let disk_number = reader.read_u16::<LittleEndian>()?;
        let internal_file_attributes = reader.read_u16::<LittleEndian>()?;
        let external_file_attributes = reader.read_u32::<LittleEndian>()?;
        let offset = reader.read_u32::<LittleEndian>()?;
        let mut file_name_raw = vec![0; file_name_length as usize];
        reader.read_exact(&mut file_name_raw)?;
        let mut extra_field = vec![0; extra_field_length as usize];
        reader.read_exact(&mut extra_field)?;
        let mut file_comment_raw = vec![0; file_comment_length as usize];
        reader.read_exact(&mut file_comment_raw)?;

        Ok(CentralDirectoryHeader {
            version_made_by,
            version_to_extract,
            flags: GeneralPurposeBitFlags(flags),
            compression_method,
            last_mod_time,
            last_mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            disk_number,
            internal_file_attributes,
            external_file_attributes,
            offset,
            file_name_raw,
            extra_field,
            file_comment_raw,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> ZipResult<()> {
        writer.write_u32::<LittleEndian>(CENTRAL_DIRECTORY_HEADER_SIGNATURE)?;
        writer.write_u16::<LittleEndian>(self.version_made_by)?;
        writer.write_u16::<LittleEndian>(self.version_to_extract)?;
        writer.write_u16::<LittleEndian>(self.flags.0)?;
        writer.write_u16::<LittleEndian>(self.compression_method)?;
        writer.write_u16::<LittleEndian>(self.last_mod_time)?;
        writer.write_u16::<LittleEndian>(self.last_mod_date)?;
        writer.write_u32::<LittleEndian>(self.crc32)?;
        writer.write_u32::<LittleEndian>(self.compressed_size)?;
        writer.write_u32::<LittleEndian>(self.uncompressed_size)?;
        writer.write_u16::<LittleEndian>(self.file_name_raw.len() as u16)?;
        writer.write_u16::<LittleEndian>(self.extra_field.len() as u16)?;
        writer.write_u16::<LittleEndian>(self.file_comment_raw.len() as u16)?;
        writer.write_u16::<LittleEndian>(self.disk_number)?;
        writer.write_u16::<LittleEndian>(self.internal_file_attributes)?;
        writer.write_u32::<LittleEndian>(self.external_file_attributes)?;
        writer.write_u32::<LittleEndian>(self.offset)?;
        writer.write_all(&self.file_name_raw)?;
        writer.write_all(&self.extra_field)?;
        writer.write_all(&self.file_comment_raw)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalFileHeader {
    pub version_to_extract: u16,
    pub flags: GeneralPurposeBitFlags,
    pub compression_method: u16,
    pub last_mod_time: u16,
    pub last_mod_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_raw: Vec<u8>,
    pub extra_field: Vec<u8>,
}

impl LocalFileHeader {
    pub fn len(&self) -> usize {
        30 + self.file_name_raw.len() + self.extra_field.len()
    }

    pub fn parse<R: Read>(reader: &mut R) -> ZipResult<LocalFileHeader> {
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != LOCAL_FILE_HEADER_SIGNATURE {
            return Err(ZipError::InvalidArchive("Invalid local file header"));
        }

        let version_to_extract = reader.read_u16::<LittleEndian>()?;
        let flags = reader.read_u16::<LittleEndian>()?;
        let compression_method = reader.read_u16::<LittleEndian>()?;
        let last_mod_time = reader.read_u16::<LittleEndian>()?;
        let last_mod_date = reader.read_u16::<LittleEndian>()?;
        let crc32 = reader.read_u32::<LittleEndian>()?;
        let compressed_size = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;
        let file_name_length = reader.read_u16::<LittleEndian>()?;
        let extra_field_length = reader.read_u16::<LittleEndian>()?;

        let mut file_name_raw = vec![0; file_name_length as usize];
        reader.read_exact(&mut file_name_raw)?;
        let mut extra_field = vec![0; extra_field_length as usize];
        reader.read_exact(&mut extra_field)?;

        Ok(LocalFileHeader {
            version_to_extract,
            flags: GeneralPurposeBitFlags(flags),
            compression_method,
            last_mod_time,
            last_mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            file_name_raw,
            extra_field,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> ZipResult<()> {
        writer.write_u32::<LittleEndian>(LOCAL_FILE_HEADER_SIGNATURE)?;
        writer.write_u16::<LittleEndian>(self.version_to_extract)?;
        writer.write_u16::<LittleEndian>(self.flags.0)?;
        writer.write_u16::<LittleEndian>(self.compression_method)?;
        writer.write_u16::<LittleEndian>(self.last_mod_time)?;
        writer.write_u16::<LittleEndian>(self.last_mod_date)?;
        writer.write_u32::<LittleEndian>(self.crc32)?;
        writer.write_u32::<LittleEndian>(self.compressed_size)?;
        writer.write_u32::<LittleEndian>(self.uncompressed_size)?;
        writer.write_u16::<LittleEndian>(self.file_name_raw.len() as u16)?;
        writer.write_u16::<LittleEndian>(self.extra_field.len() as u16)?;
        writer.write_all(&self.file_name_raw)?;
        writer.write_all(&self.extra_field)?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct DataDescriptor {
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
}

impl DataDescriptor {
    pub fn read<T: Read>(reader: &mut T) -> ZipResult<DataDescriptor> {
        let first_word = reader.read_u32::<LittleEndian>()?;
        let crc32 = if first_word == DATA_DESCRIPTOR_SIGNATURE {
            reader.read_u32::<LittleEndian>()?
        } else {
            first_word
        };
        let compressed_size = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;
        Ok(DataDescriptor {
            crc32,
            compressed_size,
            uncompressed_size,
        })
    }

    pub fn write<T: Write>(&self, writer: &mut T) -> ZipResult<()> {
        writer.write_u32::<LittleEndian>(DATA_DESCRIPTOR_SIGNATURE)?;
        writer.write_u32::<LittleEndian>(self.crc32)?;
        writer.write_u32::<LittleEndian>(self.compressed_size)?;
        writer.write_u32::<LittleEndian>(self.uncompressed_size)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{
        CentralDirectoryHeader, DataDescriptor, GeneralPurposeBitFlags, LocalFileHeader, ZipResult,
    };
    use std::io::Cursor;
    #[test]
    fn test_cdh_roundtrip() -> ZipResult<()> {
        let cdh1 = CentralDirectoryHeader {
            version_made_by: 1,
            version_to_extract: 2,
            flags: GeneralPurposeBitFlags(3),
            compression_method: 4,
            last_mod_time: 5,
            last_mod_date: 6,
            crc32: 7,
            compressed_size: 8,
            uncompressed_size: 9,
            disk_number: 10,
            internal_file_attributes: 11,
            external_file_attributes: 12,
            offset: 13,
            file_name_raw: b"a".to_vec(),
            extra_field: b"bb".to_vec(),
            file_comment_raw: b"ccc".to_vec(),
        };
        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            cdh1.write(&mut cursor)?;
        }
        let cdh2 = CentralDirectoryHeader::parse(&mut &bytes[..])?;
        assert_eq!(cdh1, cdh2);
        Ok(())
    }

    #[test]
    fn test_lfh_roundtrip() -> ZipResult<()> {
        let lfh1 = LocalFileHeader {
            version_to_extract: 1,
            flags: GeneralPurposeBitFlags(2),
            compression_method: 3,
            last_mod_time: 4,
            last_mod_date: 5,
            crc32: 6,
            compressed_size: 7,
            uncompressed_size: 8,
            file_name_raw: b"a".to_vec(),
            extra_field: b"bb".to_vec(),
        };
        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            lfh1.write(&mut cursor)?;
        }
        let lfh2 = LocalFileHeader::parse(&mut &bytes[..])?;
        assert_eq!(lfh1, lfh2);
        Ok(())
    }

    #[test]
    fn test_dd_roundtrip() -> ZipResult<()> {
        let dd1 = DataDescriptor {
            crc32: 1,
            compressed_size: 2,
            uncompressed_size: 3,
        };
        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            dd1.write(&mut cursor)?;
        }
        let dd2 = DataDescriptor::read(&mut &bytes[..])?;
        assert_eq!(dd1, dd2);
        let dd3 = DataDescriptor::read(&mut &bytes[4..])?;
        assert_eq!(dd1, dd3);
        Ok(())
    }
}
