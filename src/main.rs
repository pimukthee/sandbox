use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::libc;
use nix::sys::prctl;
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, dup2, execv, fork, pipe};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        anyhow::bail!(
            "Usage: {} <path_to_code_file> [max_time_seconds] [max_memory_mb]",
            args[0]
        );
    }

    let code_path = &args[1];

    // Parse optional arguments
    let max_time = if args.len() > 2 {
        args[2].parse::<u64>().unwrap_or(5)
    } else {
        5
    };

    let max_memory = if args.len() > 3 {
        args[3].parse::<usize>().unwrap_or(100)
    } else {
        100
    };

    // Read the code from file
    let code =
        fs::read_to_string(code_path).context(format!("Error reading file {}", code_path))?;

    // Create sandbox configuration
    let config = SandboxConfig {
        max_execution_time: Duration::from_secs(max_time),
        max_memory_mb: max_memory,
    };

    // Create and run the sandbox
    let sandbox = Sandbox::with_config(config);

    let output = sandbox
        .run(&code)
        .context("Failed to execute code in sandbox")?;
    if output.success {
        println!("=== Execution successful ===");
    } else {
        println!(
            "=== Execution failed with exit status: {:?} ===",
            output.exit_status
        );
    }

    println!("Time: {:?}", output.execution_time);

    if !output.stdout.is_empty() {
        println!("\n=== Standard Output ===\n{}", output.stdout);
    }

    if !output.stderr.is_empty() {
        println!("\n=== Standard Error ===\n{}", output.stderr);
    }
    Ok(())
}

/// Configuration for the sandbox
pub struct SandboxConfig {
    /// Maximum execution time in seconds
    pub max_execution_time: Duration,
    /// Maximum memory usage in MB
    pub max_memory_mb: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            max_execution_time: Duration::from_secs(1),
            max_memory_mb: 100,
        }
    }
}

/// Output from sandbox execution
#[derive(Debug)]
pub struct SandboxOutput {
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Whether the execution was successful
    pub success: bool,
    /// Exit status if available
    pub exit_status: Option<WaitStatus>,
    /// Execution time
    pub execution_time: Duration,
}

/// Sandbox for running arbitrary Rust code
pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    /// Create a new sandbox with default configuration
    pub fn new() -> Self {
        Sandbox {
            config: SandboxConfig::default(),
        }
    }

    /// Create a new sandbox with custom configuration
    pub fn with_config(config: SandboxConfig) -> Self {
        Sandbox { config }
    }

    /// Run Rust code in the sandbox and return the output
    pub fn run(&self, code: &str) -> anyhow::Result<SandboxOutput> {
        let mut source_path = tempfile::Builder::new()
            .prefix("rust")
            .suffix(".rs")
            .tempfile()
            .context("Failed to create tempfile")?;

        // Write the code to the file
        source_path
            .write_all(code.as_bytes())
            .context("Failed to write to tempfile")?;

        let source_path = source_path.path().to_path_buf();

        // Compile the code
        let compilation_result = self.compile(&source_path)?;
        if !compilation_result.success {
            anyhow::bail!(format!("Failed to compile {}", compilation_result.stderr));
        }

        // Run the compiled binary with restrictions
        let execution_result = self.execute(&source_path).context("Failed to execute")?;

        // Remove binary in temp dir
        let _ = fs::remove_file(source_path.with_extension(""));

        Ok(execution_result)
    }

    /// Compile the Rust source code
    fn compile(&self, source_path: &Path) -> anyhow::Result<SandboxOutput> {
        let start_time = Instant::now();

        let output = Command::new("rustc")
            .arg(source_path)
            .arg("-o")
            .arg(source_path.with_extension(""))
            .arg("-C")
            .arg("opt-level=0") // Faster compilation, less optimization
            .output()
            .context("Failed to compile")?;

        let execution_time = start_time.elapsed();

        Ok(SandboxOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            exit_status: None, // Not applicable for compilation
            execution_time,
        })
    }

    /// Execute the compiled binary with resource limitations and seccomp filters
    fn execute(&self, source_path: &Path) -> anyhow::Result<SandboxOutput> {
        let binary_path = source_path.with_extension("");

        // Create pipes for stdout and stderr
        let (stdout_reader, stdout_writer) = pipe().context("Failed to create stdout pipe")?;
        let (stderr_reader, stderr_writer) = pipe().context("Failed to create stderr pipe")?;

        // Fork the process
        match unsafe { fork()? } {
            ForkResult::Child => {
                // Close read ends of pipes
                nix::unistd::close(stdout_reader.as_raw_fd())
                    .context("Failed to close stdout reader")?;
                nix::unistd::close(stderr_reader.as_raw_fd())
                    .context("Failed to close stderr reader")?;

                // TODO: Receive input from stdin

                // Redirect stdout and stderr to pipes
                dup2(stdout_writer.as_raw_fd(), libc::STDOUT_FILENO)?;
                dup2(stderr_writer.as_raw_fd(), libc::STDERR_FILENO)?;

                // Close the original pipe file descriptors after duplication
                nix::unistd::close(stdout_writer.as_raw_fd())
                    .context("Failed to close stdout writer")?;
                nix::unistd::close(stderr_writer.as_raw_fd())
                    .context("Failed to close stderr writer")?;

                // Set resource limits
                self.set_resource_limits()?;

                // Apply security measures
                self.apply_security_measures()?;

                // Execute the binary
                let binary_cstr = std::ffi::CString::new(binary_path.to_str().unwrap()).unwrap();
                let argv = [binary_cstr.clone()];

                // This will replace the current process with the binary
                match execv(&binary_cstr, &argv) {
                    Ok(_) => unreachable!(), // execv never returns on success
                    Err(e) => {
                        let error_msg = format!("Failed to execute binary: {}\n", e);
                        // TODO: find a way use safe rust
                        unsafe {
                            let _ = libc::write(
                                libc::STDERR_FILENO,
                                error_msg.as_ptr() as *const _,
                                error_msg.len(),
                            );
                        }
                        std::process::exit(1);
                    }
                }
            }
            ForkResult::Parent { child } => {
                // Close write ends of pipes
                nix::unistd::close(stdout_writer.as_raw_fd())?;
                nix::unistd::close(stderr_writer.as_raw_fd())?;

                // Set up timeout monitoring
                let start_time = Instant::now();

                // Read output from pipes
                let mut stdout_content = String::new();
                let mut stderr_content = String::new();
                File::from(stdout_reader).read_to_string(&mut stdout_content)?;
                File::from(stderr_reader).read_to_string(&mut stderr_content)?;

                // Wait for the child process to complete
                let wait_status = waitpid(child, None)?;

                // Check execution time
                let execution_time = start_time.elapsed();

                // Process exit status
                let success = match wait_status {
                    WaitStatus::Exited(_, code) => code == 0,
                    _ => false,
                };
                // Prevent double-close fd when end of the function
                std::mem::forget(stdout_writer);
                std::mem::forget(stderr_writer);

                Ok(SandboxOutput {
                    stdout: stdout_content,
                    stderr: stderr_content,
                    success,
                    exit_status: Some(wait_status),
                    execution_time,
                })
            }
        }
    }

    /// Set resource limits for the process
    fn set_resource_limits(&self) -> anyhow::Result<()> {
        // Set CPU time limit
        let cpu_time_seconds = self.config.max_execution_time.as_secs() as u64;

        // CPU time limit
        setrlimit(Resource::RLIMIT_CPU, cpu_time_seconds, cpu_time_seconds)?;

        // Memory limit
        let memory_limit = (self.config.max_memory_mb * 1024 * 1024) as u64;
        setrlimit(Resource::RLIMIT_AS, memory_limit, memory_limit)?;

        // File size limit (prevent huge file creation)
        let file_size_limit = 5 * 1024 * 1024; // 5MB
        setrlimit(Resource::RLIMIT_FSIZE, file_size_limit, file_size_limit)?;

        setrlimit(Resource::RLIMIT_NPROC, 1, 1)?;

        Ok(())
    }

    /// Apply security measures including seccomp filters
    fn apply_security_measures(&self) -> anyhow::Result<()> {
        // Set no new privileges - prevents privilege escalation
        prctl::set_no_new_privs()
            .map_err(|e| anyhow::anyhow!(format!("Failed to set no_new_privs: {}", e)))?;

        // TODO: set up a seccomp-bpf to restrict system calls.

        Ok(())
    }
}
