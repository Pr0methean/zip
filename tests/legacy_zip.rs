#![cfg(feature = "legacy-zip")]

use std::io::{self, Read};
use zip::ZipArchive;

#[test]
fn decompress_shrink() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/shrink.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).expect("couldn't open test zip file");

    let mut file = archive
        .by_name("FIRST.TXT")
        .expect("couldn't find file in archive");
    assert_eq!("FIRST.TXT", file.name());

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(include_bytes!("data/folder/first.txt"), &content[..]);
}

#[test]
fn decompress_reduce() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/reduce.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).expect("couldn't open test zip file");

    let mut file = archive
        .by_name("first.txt")
        .expect("couldn't find file in archive");
    assert_eq!("first.txt", file.name());

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(include_bytes!("data/folder/first.txt"), &content[..]);
}

#[test]
fn decompress_implode() {
    let mut v = Vec::new();
    v.extend_from_slice(include_bytes!("data/implode.zip"));
    let mut archive = ZipArchive::new(io::Cursor::new(v)).expect("couldn't open test zip file");

    let mut file = archive
        .by_name("first.txt")
        .expect("couldn't find file in archive");
    assert_eq!("first.txt", file.name());

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .expect("couldn't read encrypted and compressed file");
    assert_eq!(include_bytes!("data/folder/first.txt"), &content[..]);
}
