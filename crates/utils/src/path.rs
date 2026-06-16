// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::PathBuf;

/// Enumerates a PathBuf by inserting an index before the file extension
/// or at the end if there is no extension
///
/// Examples:
/// - "/foo/bar/thing.pdf" -> "/foo/bar/thing.0.pdf"
/// - "/foo/bar/thing" -> "/foo/bar/thing.0"
pub fn enumerate_path(path: &std::path::Path, index: usize) -> PathBuf {
    if let Some(parent) = path.parent() {
        if let Some(file_name) = path.file_name() {
            if let Some(file_name_str) = file_name.to_str() {
                if let Some(dot_pos) = file_name_str.rfind('.') {
                    // Has extension
                    let (stem, extension) = file_name_str.split_at(dot_pos);
                    let new_name = format!("{}.{}{}", stem, index, extension);
                    parent.join(new_name)
                } else {
                    // No extension
                    let new_name = format!("{}.{}", file_name_str, index);
                    parent.join(new_name)
                }
            } else {
                // Invalid UTF-8 in filename, append index directly
                let new_name = format!("{}.{}", file_name.to_string_lossy(), index);
                parent.join(new_name)
            }
        } else {
            // Path ends with '/', just append index
            path.join(format!("{}", index))
        }
    } else {
        // No parent, just modify the filename directly
        if let Some(file_name) = path.file_name() {
            if let Some(file_name_str) = file_name.to_str() {
                if let Some(dot_pos) = file_name_str.rfind('.') {
                    // Has extension
                    let (stem, extension) = file_name_str.split_at(dot_pos);
                    let new_name = format!("{}.{}{}", stem, index, extension);
                    PathBuf::from(new_name)
                } else {
                    // No extension
                    let new_name = format!("{}.{}", file_name_str, index);
                    PathBuf::from(new_name)
                }
            } else {
                // Invalid UTF-8 in filename, append index directly
                let new_name = format!("{}.{}", file_name.to_string_lossy(), index);
                PathBuf::from(new_name)
            }
        } else {
            // Empty path, just return the index as a path
            PathBuf::from(format!("{}", index))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_path_with_extension() {
        let path = PathBuf::from("/foo/bar/thing.pdf");
        let result = enumerate_path(&path, 0);
        assert_eq!(result, PathBuf::from("/foo/bar/thing.0.pdf"));
    }

    #[test]
    fn test_enumerate_path_without_extension() {
        let path = PathBuf::from("/foo/bar/thing");
        let result = enumerate_path(&path, 5);
        assert_eq!(result, PathBuf::from("/foo/bar/thing.5"));
    }

    #[test]
    fn test_enumerate_path_no_parent() {
        let path = PathBuf::from("thing.txt");
        let result = enumerate_path(&path, 1);
        assert_eq!(result, PathBuf::from("thing.1.txt"));
    }

    #[test]
    fn test_enumerate_path_empty() {
        let path = PathBuf::from("");
        let result = enumerate_path(&path, 2);
        assert_eq!(result, PathBuf::from("2"));
    }
}
