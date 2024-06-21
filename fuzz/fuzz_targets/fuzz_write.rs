#![no_main]

use arbitrary::Arbitrary;
use core::fmt::{Debug, Formatter};
use std::borrow::Cow;
use libfuzzer_sys::fuzz_target;
use replace_with::replace_with_or_abort;
use std::io::{Cursor, Read, Seek, Write};
use std::path::PathBuf;
use zip::unstable::path_to_string;

#[derive(Arbitrary, Clone)]
pub enum BasicFileOperation<'k> {
    WriteNormalFile {
        contents: Box<[Box<[u8]>]>,
        options: zip::write::FullFileOptions<'k>,
    },
    WriteDirectory(zip::write::FullFileOptions<'k>),
    WriteSymlinkWithTarget {
        target: PathBuf,
        options: zip::write::FullFileOptions<'k>,
    },
    ShallowCopy(Box<FileOperation<'k>>),
    DeepCopy(Box<FileOperation<'k>>),
    MergeWithOtherFile {
        operations: Box<[(FileOperation<'k>, bool)]>
    },
    SetArchiveComment(Box<[u8]>)
}

#[derive(Arbitrary, Clone, Debug, Eq, PartialEq)]
pub enum ReopenOption {
    DoNotReopen,
    ViaFinish,
    ViaFinishIntoReadable
}

#[derive(Arbitrary, Clone)]
pub struct FileOperation<'k> {
    basic: BasicFileOperation<'k>,
    path: PathBuf,
    reopen: ReopenOption,
    // 'abort' flag is separate, to prevent trying to copy an aborted file
}

impl <'k> FileOperation<'k> {
    fn get_path(&self) -> Option<Cow<PathBuf>> {
        match &self.basic {
            BasicFileOperation::SetArchiveComment(_) => None,
            BasicFileOperation::WriteDirectory(_) => Some(Cow::Owned(self.path.join("/"))),
            BasicFileOperation::MergeWithOtherFile { operations } =>
                operations.iter().flat_map(|(op, abort)| if !abort { op.get_path() } else { None }).next(),
            _ => Some(Cow::Borrowed(&self.path))
        }
    }
}

impl <'k> Debug for FileOperation<'k> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.basic {
            BasicFileOperation::WriteNormalFile {contents, options} => {
                f.write_fmt(format_args!("let options = {:?};\n\
                writer.start_file_from_path({:?}, options)?;\n", options, self.path))?;
                for content_slice in contents {
                    f.write_fmt(format_args!("writer.write_all(&({:?}))?;\n", content_slice))?;
                }
            },
            BasicFileOperation::WriteDirectory(options) => {
                f.write_fmt(format_args!("let options = {:?};\n\
                writer.add_directory_from_path({:?}, options)?;\n",
                             options, self.path))?;
            },
            BasicFileOperation::WriteSymlinkWithTarget {target, options} => {
                f.write_fmt(format_args!("let options = {:?};\n\
                writer.add_symlink_from_path({:?}, {:?}, options)?;\n",
                             options, self.path, target.to_owned()))?;
            },
            BasicFileOperation::ShallowCopy(base) => {
                let Some(base_path) = base.get_path() else {
                    return Ok(())
                };
                f.write_fmt(format_args!("{:?}writer.shallow_copy_file_from_path({:?}, {:?})?;\n", base, base_path, self.path))?;
            },
            BasicFileOperation::DeepCopy(base) => {
                let Some(base_path) = base.get_path() else {
                    return Ok(())
                };
                f.write_fmt(format_args!("{:?}writer.deep_copy_file_from_path({:?}, {:?})?;\n", base, base_path, self.path))?;
            },
            BasicFileOperation::MergeWithOtherFile {operations} => {
                f.write_str("let sub_writer = {\n\
                    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));\n\
                    writer.set_flush_on_finish_file(false);\n")?;
                operations.iter().map(|op| {
                    f.write_fmt(format_args!("{:?}", op.0))?;
                    if op.1 {
                        f.write_str("writer.abort_file()?;\n")
                    } else {
                        Ok(())
                    }
                }).collect::<Result<(), _>>()?;
                f.write_str("writer\n\
                };\n\
                writer.merge_archive(sub_writer.finish_into_readable()?)?;\n")?;
            },
            BasicFileOperation::SetArchiveComment(comment) => {
                f.write_fmt(format_args!("writer.set_raw_comment({:?}.into());\n", comment))?;
            }
        }
        match &self.reopen {
            ReopenOption::DoNotReopen => Ok(()),
            ReopenOption::ViaFinish => {
                f.write_str("writer = ZipWriter::new_append(writer.finish()?)?;\n")
            },
            ReopenOption::ViaFinishIntoReadable => {
                f.write_str("writer = ZipWriter::new_append(writer.finish_into_readable()?.into_inner())?;\n")
            }
        }
    }
}

#[derive(Arbitrary, Clone)]
pub struct FuzzTestCase<'k> {
    operations: Box<[(FileOperation<'k>, bool)]>,
    flush_on_finish_file: bool,
}

impl <'k> Debug for FuzzTestCase<'k> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "let mut writer = ZipWriter::new(Cursor::new(Vec::new()));\n\
            writer.set_flush_on_finish_file({:?});\n", self.flush_on_finish_file))?;
        self.operations.iter().map(|op| {
            f.write_fmt(format_args!("{:?}", op.0))?;
            if op.1 {
                f.write_str("writer.abort_file()?;\n")
            } else {
                Ok(())
            }
        })
            .collect::<Result<(), _>>()?;
        f.write_str("writer\n")
    }
}

fn deduplicate_paths(copy: &mut Cow<PathBuf>, original: &PathBuf) {
    if path_to_string(&**copy) == path_to_string(original) {
        let new_path = match original.file_name() {
            Some(name) => {
                let mut new_name = name.to_owned();
                new_name.push("_copy");
                copy.with_file_name(new_name)
            },
            None => copy.with_file_name("copy")
        };
        *copy = Cow::Owned(new_path);
    }
}

fn do_operation<'k, T>(
    writer: &mut zip::ZipWriter<T>,
    operation: &FileOperation<'k>,
    abort: bool,
    flush_on_finish_file: bool,
    files_added: &mut usize
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Read + Write + Seek,
{
    println!("do_operation(writer, {:?}, {:?}, {:?}, {:?})", operation, abort, flush_on_finish_file, files_added);
    writer.set_flush_on_finish_file(flush_on_finish_file);
    let mut path = Cow::Borrowed(&operation.path);
    match &operation.basic {
        BasicFileOperation::WriteNormalFile {
            contents,
            options,
            ..
        } => {
            let uncompressed_size = contents.iter().map(|chunk| chunk.len()).sum::<usize>();
            let mut options = (*options).to_owned();
            if uncompressed_size >= u32::MAX as usize {
                options = options.large_file(true);
            }
            writer.start_file_from_path(&*path, options)?;
            for chunk in contents.iter() {
                writer.write_all(&chunk)?;
            }
            *files_added += 1;
        }
        BasicFileOperation::WriteDirectory(options) => {
            writer.add_directory_from_path(&*path, options.to_owned())?;
            *files_added += 1;
        }
        BasicFileOperation::WriteSymlinkWithTarget { target, options } => {
            writer.add_symlink_from_path(&*path, target, options.to_owned())?;
            *files_added += 1;
        }
        BasicFileOperation::ShallowCopy(base) => {
            let Some(base_path) = base.get_path() else {
                println!("Skipping ShallowCopy because no base_path");
                return Ok(());
            };
            deduplicate_paths(&mut path, &base_path);
            do_operation(writer, &base, false, flush_on_finish_file, files_added)?;
            println!("Shallow copying {:?} to {:?}", base_path, path);
            writer.shallow_copy_file_from_path(&*base_path, &*path)?;
            *files_added += 1;
        }
        BasicFileOperation::DeepCopy(base) => {
            let Some(base_path) = base.get_path() else {
                println!("Skipping DeepCopy because no base_path");
                return Ok(());
            };
            deduplicate_paths(&mut path, &base_path);
            do_operation(writer, &base, false, flush_on_finish_file, files_added)?;
            println!("Deep copying {:?} to {:?}", base_path, path);
            writer.deep_copy_file_from_path(&*base_path, &*path)?;
            *files_added += 1;
        }
        BasicFileOperation::MergeWithOtherFile { operations } => {
            let mut other_writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let mut inner_files_added = 0;
            operations.iter().for_each(|(operation, abort)| {
                let _ = do_operation(
                    &mut other_writer,
                    &operation,
                    *abort,
                    false,
                    &mut inner_files_added
                );
            });
            writer.merge_archive(other_writer.finish_into_readable()?)?;
            *files_added += inner_files_added;
        },
        BasicFileOperation::SetArchiveComment(comment) => {
            writer.set_raw_comment(comment.clone());
        }
    }
    if abort && *files_added != 0 {
        println!("Calling abort_file()");
        writer.abort_file()?;
        *files_added -= 1;
    }
    // If a comment is set, we finish the archive, reopen it for append and then set a shorter
    // comment, then there will be junk after the new comment that we can't get rid of. Thus, we
    // can only check that the expected is a prefix of the actual
    match operation.reopen {
        ReopenOption::DoNotReopen => return Ok(()),
        ReopenOption::ViaFinish => {
            let old_comment = writer.get_raw_comment().to_owned();
            println!("ViaFinish: old_comment: {:?}", old_comment);
            replace_with_or_abort(writer, |old_writer: zip::ZipWriter<T>| {
                zip::ZipWriter::new_append(old_writer.finish().unwrap()).unwrap()
            });
            println!("writer.get_raw_comment(): {:?}", writer.get_raw_comment());
            assert!(writer.get_raw_comment().starts_with(&old_comment));
        },
        ReopenOption::ViaFinishIntoReadable => {
            let old_comment = writer.get_raw_comment().to_owned();
            println!("ViaFinishIntoReadable: {:?}", writer);
            replace_with_or_abort(writer, |old_writer: zip::ZipWriter<T>| {
                zip::ZipWriter::new_append(old_writer.finish_into_readable().unwrap().into_inner()).unwrap()
            });
            println!("writer: {:?}", writer);
            assert!(writer.get_raw_comment().starts_with(&old_comment));
        },
    }
    Ok(())
}

fuzz_target!(|test_case: FuzzTestCase| {
    let mut files_added = 0;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut final_reopen = false;
    if let Some((last_op, _)) = test_case.operations.last() {
        if last_op.reopen != ReopenOption::ViaFinishIntoReadable {
            final_reopen = true;
        }
    }
    #[allow(unknown_lints)]
    #[allow(boxed_slice_into_iter)]
    for (operation, abort) in test_case.operations.into_iter() {
        let _ = do_operation(
            &mut writer,
            &operation,
            *abort,
            test_case.flush_on_finish_file,
            &mut files_added
        );
    }
    if final_reopen {
        let _ = writer.finish_into_readable().unwrap();
    }
});
