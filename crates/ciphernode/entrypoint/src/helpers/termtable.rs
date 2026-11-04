// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub fn print_table(headers: &[&str], data: &[Vec<String>]) {
    // Calculate the maximum width needed for each column
    let mut col_widths = vec![0; headers.len()];

    // Check widths from headers
    for (i, header) in headers.iter().enumerate() {
        col_widths[i] = header.len();
    }

    // Check widths from data
    for row in data {
        for (i, cell) in row.iter().enumerate() {
            if i < col_widths.len() && cell.len() > col_widths[i] {
                col_widths[i] = cell.len();
            }
        }
    }

    // Print headers
    for (i, header) in headers.iter().enumerate() {
        print!("{:<width$} ", header, width = col_widths[i] + 1);
    }
    println!();

    // Print data
    for row in data {
        for (i, cell) in row.iter().enumerate() {
            if i < col_widths.len() {
                print!("{:<width$} ", cell, width = col_widths[i] + 1);
            }
        }
        println!();
    }
}
