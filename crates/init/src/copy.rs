// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_fs::prelude::*;
use e3_fs::Fs;
use regex::Regex;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone)]
pub struct Filter {
    pub glob_pattern: String,
    pub search_pattern: String,
    pub replacement: String,
}
impl Filter {
    pub fn new(glob_pattern: &str, search_pattern: &str, replacement: &str) -> Self {
        Filter {
            glob_pattern: glob_pattern.to_string(),
            search_pattern: search_pattern.to_string(),
            replacement: replacement.to_string(),
        }
    }
}

pub async fn copy_with_filters_impl<P1, P2>(
    fs: &Fs,
    src_path: P1,
    dest_path: P2,
    filters: &[Filter],
) -> Result<()>
where
    P1: AsRef<Path> + Send + Sync,
    P2: AsRef<Path> + Send + Sync,
{
    info!("mkdirp {:?}", dest_path.as_ref());
    fs.mkdirp(&dest_path).await?;
    info!("cp -r {:?} {:?}", src_path.as_ref(), dest_path.as_ref());
    fs.cp(&src_path, &dest_path).await?;

    for filter in filters {
        info!("Running filter: {:?}", filter);

        let file_paths = fs.find_files(&dest_path, &filter.glob_pattern).await?;
        info!("pattern:{} found {:?}", filter.glob_pattern, file_paths);

        for file_path in file_paths {
            fs.replace_in_place(
                &Regex::new(&filter.search_pattern)?,
                &filter.replacement,
                file_path,
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn copy_with_filters<P1, P2>(
    src_path: P1,
    dest_path: P2,
    filters: &[Filter],
) -> Result<()>
where
    P1: AsRef<Path> + Send + Sync,
    P2: AsRef<Path> + Send + Sync,
{
    info!(
        "src: {:?} dest: {:?}",
        src_path.as_ref(),
        dest_path.as_ref()
    );

    copy_with_filters_impl(
        &Fs::physical()?,
        src_path.as_ref().join("."),
        dest_path,
        filters,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use e3_fs::Fs;
    #[tokio::test]
    async fn test_copy_with_filters_impl() -> Result<()> {
        // Create an in-memory filesystem
        let fs = Fs::mem();
        // Define source and destination paths
        let src_path = "/tmp/mysource/.";
        let dest_path = "/home/user/myproj";
        fs.mkdirp(dest_path).await?;
        // Create some test files in the source directory
        fs.mkdirp(src_path).await?;
        fs.write_to_file(format!("{}/file1.txt", src_path), "Content of file 1")
            .await?;
        fs.write_to_file(format!("{}/file2.txt", src_path), "Content of file 2")
            .await?;
        fs.mkdirp(format!("{}/subdir", src_path)).await?;
        fs.write_to_file(
            format!("{}/subdir/file3.txt", src_path),
            "Content of file 3",
        )
        .await?;
        // Create a nested directory structure with a package.json file
        fs.mkdirp(format!(
            "{}/tools/build/scripts/utils/helper-tool",
            src_path
        ))
        .await?;
        fs.write_to_file(
            format!(
                "{}/tools/build/scripts/utils/helper-tool/package.json",
                src_path
            ),
            r#"{
  "name": "helper-tool",
  "version": "1.0.0",
  "description": "A simple utility tool",
  "main": "index.js",
  "dependencies": {
    "lodash": "^4.17.21"
  }
}"#,
        )
        .await?;

        // Execute the copy operation
        copy_with_filters_impl(
            &fs,
            &src_path,
            &dest_path,
            &[
                Filter::new(
                    "**/*/package.json",
                    r#""lodash":\s*"[^"]*""#,
                    r#""lodash": "1.0.0""#,
                ),
                // Filter::new("package.json", "lodash", "nodash"),
                Filter::new("**/*/file3.txt", "file", "chicken"),
            ],
        )
        .await?;

        // Verify that files were copied to the destination
        // Check that the original files exist in source
        assert!(fs
            .read_to_string(format!("{}/file1.txt", src_path))
            .await
            .is_ok());
        assert!(fs
            .read_to_string(format!("{}/file2.txt", src_path))
            .await
            .is_ok());
        assert!(fs
            .read_to_string(format!("{}/subdir/file3.txt", src_path))
            .await
            .is_ok());

        // Check that files were copied to destination
        let copied_file1 = fs
            .read_to_string(format!("{}/file1.txt", dest_path))
            .await?;
        let copied_file2 = fs
            .read_to_string(format!("{}/file2.txt", dest_path))
            .await?;
        let copied_file3 = fs
            .read_to_string(format!("{}/subdir/file3.txt", dest_path))
            .await?;
        let copied_package_json = fs
            .read_to_string(format!(
                "{}/tools/build/scripts/utils/helper-tool/package.json",
                dest_path
            ))
            .await?;
        let new_package_json = fs
            .read_to_string(format!(
                "{}/tools/build/scripts/utils/helper-tool/package.json",
                dest_path
            ))
            .await?;

        assert_eq!(
            new_package_json,
            r#"{
  "name": "helper-tool",
  "version": "1.0.0",
  "description": "A simple utility tool",
  "main": "index.js",
  "dependencies": {
    "lodash": "1.0.0"
  }
}"#,
        );

        // Verify content matches
        assert_eq!(copied_file1, "Content of file 1");
        assert_eq!(copied_file2, "Content of file 2");
        assert_eq!(copied_file3, "Content of chicken 3"); // substitution
        assert!(copied_package_json.contains("helper-tool"));
        assert!(copied_package_json.contains("lodash"));

        // Additional verification: check that the source files still exist (copy, not move)
        let original_file1 = fs.read_to_string(format!("{}/file1.txt", src_path)).await?;
        let original_file2 = fs.read_to_string(format!("{}/file2.txt", src_path)).await?;
        let original_file3 = fs
            .read_to_string(format!("{}/subdir/file3.txt", src_path))
            .await?;
        let original_package_json = fs
            .read_to_string(format!(
                "{}/tools/build/scripts/utils/helper-tool/package.json",
                src_path
            ))
            .await?;
        assert_eq!(original_file1, "Content of file 1");
        assert_eq!(original_file2, "Content of file 2");
        assert_eq!(original_file3, "Content of file 3");
        assert!(original_package_json.contains("helper-tool"));
        assert!(original_package_json.contains("lodash"));
        Ok(())
    }
}
