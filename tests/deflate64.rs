#![cfg(feature = "deflate64")]

use std::io::{self, Read};
use zip::ZipArchive;

#[test]
fn decompress_deflate64() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/deflate64.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).expect("couldn't open test zip file");

    let mut file = archive
        .by_name("binary.wmv")
        .expect("couldn't find file in archive");
    assert_eq!("binary.wmv", file.name());

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(include_bytes!("data/folder/binary.wmv"), &content[..]);
}

#[test]
fn decompress_deflate64_stream_no_data_descriptor() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/deflate64.zip"));
    let mut stream = io::Cursor::new(v);

    let mut entry = zip::read::read_zipfile_from_seekablestream(&mut stream)
        .expect("couldn't open test zip file")
        .expect("did not find file entry in zip file");
    assert_eq!("binary.wmv", entry.name());

    let mut content = Vec::new();
    entry
        .read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(include_bytes!("data/folder/binary.wmv"), &content[..]);
}

#[test]
fn decompress_deflate64_stream_with_data_descriptor_sanity_check() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/data_descriptor.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).expect("couldn't open test zip file");

    let mut file = archive
        .by_name("hello.txt")
        .expect("couldn't find file in archive");
    assert_eq!("hello.txt", file.name());

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(b"Hello World\n", &content[..]);
}

#[test]
fn decompress_deflate64_stream_with_data_descriptor() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/data_descriptor.zip"));
    let mut stream = io::Cursor::new(v);

    let mut entry = zip::read::read_zipfile_from_seekablestream(&mut stream)
        .expect("couldn't open test zip file")
        .expect("did not find file entry in zip file");
    assert_eq!("hello.txt", entry.name());

    let mut content = Vec::new();
    entry
        .read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(b"Hello World\n", &content[..]);
}

#[test]
fn decompress_deflate64_stream_with_data_descriptor_continue() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/data_descriptor_two_entries.zip"));
    let mut stream = io::Cursor::new(v);

    // First entry

    let mut entry = zip::read::read_zipfile_from_seekablestream(&mut stream)
        .expect("couldn't open test zip file")
        .expect("did not find file entry in zip file");
    assert_eq!("hello.txt", entry.name());

    let mut content = Vec::new();
    entry
        .read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(b"Hello World\n", &content[..]);

    drop(entry);

    // Second entry

    zip::read::advance_stream_to_next_zipfile_start(&mut stream)
        .expect("couldn't advance to next entry in zip file");

    let mut entry = zip::read::read_zipfile_from_seekablestream(&mut stream)
        .expect("couldn't open test zip file")
        .expect("did not find file entry in zip file");
    assert_eq!("world.txt", entry.name());

    let mut content = Vec::new();
    entry
        .read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(b"STUFF\n", &content[..]);

    drop(entry);

    // No more entries

    let entry = zip::read::advance_stream_to_next_zipfile_start(&mut stream)
        .expect("couldn't advance to next entry in zip file");
    match entry {
        None => (),
        _ => assert!(false, "expected no more entries"),
    };
}
