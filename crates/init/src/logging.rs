// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::future::Future;
use tokio::time::{sleep, Duration};

/// A progress spinner for displaying async task status with optional verbose output.
///
/// `TaskSpinner` provides a clean way to show progress for long-running operations,
/// with support for both animated spinner mode and verbose text output.
///
/// # Examples
///
/// ```ignore
/// use task_spinner::TaskSpinner;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let mut spinner = TaskSpinner::new("Initializing", false);
///     
///     // Run a task with the spinner
///     let result = spinner.run("Downloading files", || async {
///         // Your async work here
///         download_files().await?;
///         Ok(())
///     }).await?;
///     
///     // Update progress
///     spinner.update("Files downloaded").await;
///     
///     // Mark as complete
///     spinner.done("✅ All tasks completed").await?;
///     
///     Ok(())
/// }
pub struct TaskSpinner {
    spinner: ProgressBar,
    verbose: bool,
}

impl TaskSpinner {
    /// Creates a new `TaskSpinner` with an initial message.
    ///
    /// # Arguments
    ///
    /// * `message` - The initial message to display alongside the spinner
    /// * `verbose` - If `true`, displays plain text output instead of animated spinner
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Create a spinner with animation
    /// let spinner = TaskSpinner::new("Loading data", false);
    ///
    /// // Create a spinner in verbose mode (no animation, just text)
    /// let verbose_spinner = TaskSpinner::new("Loading data", true);
    /// ```
    pub fn new(message: impl Into<String>, verbose: bool) -> Self {
        let spinner = if verbose {
            // Hidden spinner in verbose mode - we just print text
            ProgressBar::hidden()
        } else {
            // Animated spinner in normal mode
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
            );
            pb.enable_steady_tick(Duration::from_millis(100));
            pb
        };

        let msg = message.into();
        if !msg.is_empty() {
            if verbose {
                println!("{}", msg);
            } else {
                spinner.set_message(msg);
            }
        }

        Self { spinner, verbose }
    }

    /// Runs an async task while displaying a progress message.
    ///
    /// This method executes the provided async closure while showing either
    /// a spinning animation or verbose text output, depending on the spinner's mode.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to display while the task is running
    /// * `task` - An async closure that performs the actual work
    ///
    /// # Returns
    ///
    /// Returns the result of the async task, propagating any errors that occur.
    ///
    /// # Type Parameters
    ///
    /// * `F` - The closure type
    /// * `Fut` - The future type returned by the closure
    /// * `T` - The success type returned by the future
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut spinner = TaskSpinner::new("Starting", false);
    ///
    /// let result = spinner.run("Processing data", || async {
    ///     // Perform some async operation
    ///     process_data().await?;
    ///     Ok(42)
    /// }).await?;
    ///
    /// assert_eq!(result, 42);
    /// ```
    ///
    /// # Notes
    ///
    /// In verbose mode, this will print the message to stdout.
    /// In normal mode, the spinner continues to animate during task execution.
    pub async fn run<F, Fut, T>(&mut self, message: impl Into<String>, task: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        if self.verbose {
            println!("{}", message.into());
        }

        let res = task().await;

        match res {
            Ok(res) => Ok(res),
            Err(e) => {
                if !self.verbose {
                    self.spinner.finish_and_clear();
                }
                Err(e)
            }
        }
    }

    /// Updates the spinner with a completion message for the current step.
    ///
    /// This method briefly pauses execution, then displays a success message
    /// with a checkmark. The spinner animation continues after the update.
    ///
    /// # Arguments
    ///
    /// * `message` - The completion message to display
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut spinner = TaskSpinner::new("Working", false);
    ///
    /// // Perform some work...
    /// spinner.update("Step 1 completed").await;
    ///
    /// // Continue with more work...
    /// spinner.update("Step 2 completed").await;
    /// ```
    ///
    /// # Notes
    ///
    /// - Adds a 500ms delay before showing the update for better visual flow
    /// - Temporarily suspends the spinner to print the message cleanly
    pub async fn update(&mut self, message: impl Into<String>) {
        sleep(Duration::from_millis(500)).await;

        self.spinner.suspend(|| {
            println!("🏗️  {}", message.into());
        });
    }

    /// Marks the current task as complete with a success message.
    ///
    /// This method suspends the spinner, prints a checkmark message,
    /// and then clears the spinner message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to display when the task is completed
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut spinner = TaskSpinner::new("Processing", false);
    ///
    /// // Perform some processing...
    /// spinner.complete_task("Task completed successfully").await;
    /// ```
    ///
    /// # Notes
    ///
    /// - This method is useful for marking individual tasks as done
    ///   within a larger operation, while keeping the spinner active.
    /// - The spinner will continue to animate until `done()` is called.
    pub fn complete_task(&mut self, message: impl Into<String>) {
        self.spinner.suspend(|| {
            println!("✅ {}", message.into());
        });
    }

    /// Completes the spinner with a final message.
    ///
    /// This method stops the spinner animation and replaces it with
    /// the provided completion message. Use this when all tasks are finished.
    ///
    /// # Arguments
    ///
    /// * `message` - The final message to display
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` for convenience in error propagation chains.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut spinner = TaskSpinner::new("Installing", false);
    ///
    /// // Do installation work...
    ///
    /// spinner.done("✅ Installation complete!").await?;
    /// ```
    ///
    /// # Notes
    ///
    /// After calling `done()`, the spinner is finished and should not be reused.
    /// The final message remains visible in the terminal.
    pub fn done(&mut self, message: impl Into<String>) {
        self.spinner.finish_and_clear();
        println!("{}", message.into());
    }
}
