mod cli;

use clap::Parser;
use cli::{Cli, EncryptDecryptOptions, PasswordOptions};
use rpassword;
use std::{
    path::Path,
    process::{self, Command},
};
use thiserror::Error;

#[derive(Error, Debug)]
enum EncryptError {
    #[error("expected an environment variable but failed to get it")]
    EnvVarError,
    #[error("failed to read a file")]
    FileError,
    #[error("prompted for a password but it couldn't be read")]
    PromptError,
    #[error("failed to read piped input")]
    PipeError,
}

fn main() {
    let c = Cli::parse();
    let verbosity = c.verbose;
    let pass = match get_pass(c.pass_option, verbosity) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to get a password: {e}");
            return;
        }
    };
    if verbosity >= 1 {
        println!("Successfully read password");
    }

    match c.command {
        cli::Commands::Encrypt(opts) => handle_encrypt_decrypt(true, opts, pass, verbosity),
        cli::Commands::Decrypt(opts) => handle_encrypt_decrypt(false, opts, pass, verbosity),
        cli::Commands::Git {} => todo!(),
    }
}

/// Encrypts if encrypt is true and decrypts if it is false
fn handle_encrypt_decrypt(
    encrypt: bool,
    opts: EncryptDecryptOptions,
    password: String,
    verbosity: u8,
) {
    if opts.input.is_empty() {
        println!("The input path cannot be empty");
        return;
    }
    let input_path = Path::new(&opts.input);
    if input_path.is_file() {
        if opts.output.replace {
            let res = if encrypt {
                encrypt_file(opts.input.clone(), password, None, opts.force)
            } else {
                decrypt_file(opts.input.clone(), password, None, opts.force)
            };
            if res.is_err() {
                println!("Something went wrong encrypting/decrypting the file");
                return;
            }
        } else {
            let output_path = opts.output.output.unwrap();
            if output_path.is_empty() {
                println!("The output path cannot be empty");
                return;
            }
            if Path::new(&output_path).exists() && !opts.force {
                println!("This file or directory already exists.\nDelete it or rerun the command with --force");
                return;
            }
        }
    } else {
        todo!()
    }
}

fn get_pass(opts: PasswordOptions, verbosity: u8) -> Result<String, EncryptError> {
    // Read from the environment variable
    if let Some(env) = opts.password_env {
        if verbosity >= 2 {
            println!("Attempting to read password from an envrionment variable");
        }
        if let Ok(pass) = std::env::var(env) {
            Ok(pass)
        } else {
            return Err(EncryptError::EnvVarError);
        }
    // Read from a file
    } else if let Some(file) = opts.password_file {
        if verbosity >= 2 {
            println!("Attempting to read password from a file");
        }
        let contents = std::fs::read_to_string(file);
        let Ok(contents) = contents else {
            return Err(EncryptError::FileError);
        };
        return Ok(contents);
    // Read as an arugment
    } else if let Some(pass) = opts.password {
        return Ok(pass);
    // Read from stdin to check for a password there
    } else {
        if verbosity >= 2 {
            println!("Checking whether standard input is redirected");
        }
        if atty::is(atty::Stream::Stdin) {
            // Stdin isn't redirected so no pipe
            if verbosity >= 2 {
                println!("Prompting user for password");
            }
            if let Ok(pass) = rpassword::prompt_password("Enter password: ") {
                return Ok(pass);
            } else {
                return Err(EncryptError::PromptError);
            }
        } else {
            if verbosity >= 2 {
                println!("Reading password from standard input");
            }
            let mut pass = String::new();
            if let Ok(_) = std::io::stdin().read_line(&mut pass) {
                return Ok(pass);
            } else {
                return Err(EncryptError::PipeError);
            }
        }
    }
}

// fn handle_encrypt_decrypt(opts: EncryptDecryptOptions) {

// }

/// Encrypt a given file
///
/// If output_file is None, then overwrite the input file
fn encrypt_file(
    input_file: String,
    password: String,
    mut output_file: Option<String>,
    force: bool,
) -> Result<(), ()> {
    // Check that the files aren't the same
    output_file = if output_file == Some(input_file.clone()) {
        None
    } else {
        output_file
    };
    match output_file {
        Some(out_file) => {
            let status = if !force {
                Command::new("gpg")
                    .args([
                        "--output",
                        &out_file,
                        "--symmetric",
                        "--cipher-algo",
                        "AES256",
                        "--batch",
                        "--passphrase",
                        &password,
                        &input_file,
                    ])
                    .status()
            } else {
                Command::new("gpg")
                    .args([
                        "--output",
                        &out_file,
                        "--symmetric",
                        "--cipher-algo",
                        "AES256",
                        "--batch",
                        "--yes",
                        "--passphrase",
                        &password,
                        &input_file,
                    ])
                    .status()
            };

            let Ok(status) = status else {
                println!("Something went wrong in running gpg");
                process::exit(1);
            };

            if status.success() {
                return Ok(());
            } else {
                return Err(());
            }
        }
        None => {
            let status = Command::new("gpg")
                .args([
                    "--output",
                    &format!("{}.tmp.denc", input_file),
                    "--symmetric",
                    "--cipher-algo",
                    "AES256",
                    "--batch",
                    "--yes",
                    "--passphrase",
                    &password,
                    &input_file,
                ])
                .status();

            let Ok(status) = status else {
                println!("Something went wrong in running gpg");
                process::exit(1);
            };

            if !status.success() {
                return Err(());
            }

            let res = std::fs::rename(format!("{}.tmp.denc", input_file), input_file);
            match res {
                Ok(_) => return Ok(()),
                Err(e) => {
                    println!("Failed to rename a file: {e}\nWarning: you may need to remove files ending in .tmp.denc");
                    return Err(());
                }
            }
        }
    };
}

/// Decrypt a given file
///
/// If output_file is None, then overwrite the input file
fn decrypt_file(
    input_file: String,
    password: String,
    mut output_file: Option<String>,
    force: bool,
) -> Result<(), ()> {
    // Check that the files aren't the same
    output_file = if output_file == Some(input_file.clone()) {
        None
    } else {
        output_file
    };
    match output_file {
        Some(out_file) => {
            let status = if !force {
                Command::new("gpg")
                    .args([
                        "--output",
                        &out_file,
                        "--batch",
                        "--passphrase",
                        &password,
                        "--decrypt",
                        &input_file,
                    ])
                    .status()
            } else {
                Command::new("gpg")
                    .args([
                        "--output",
                        &out_file,
                        "--batch",
                        "--yes",
                        "--passphrase",
                        &password,
                        "--decrypt",
                        &input_file,
                    ])
                    .status()
            };

            let Ok(status) = status else {
                println!("Something went wrong in running gpg");
                process::exit(1);
            };

            if status.success() {
                return Ok(());
            } else {
                return Err(());
            }
        }
        None => {
            let status = Command::new("gpg")
                .args([
                    "--output",
                    &format!("{}.tmp.denc", input_file),
                    "--batch",
                    "--passphrase",
                    &password,
                    "--decrypt",
                    &input_file,
                ])
                .status();

            let Ok(status) = status else {
                println!("Something went wrong in running gpg");
                process::exit(1);
            };

            if !status.success() {
                return Err(());
            }

            let res = std::fs::rename(format!("{}.tmp.denc", input_file), input_file);
            match res {
                Ok(_) => return Ok(()),
                Err(e) => {
                    println!("Failed to rename a file: {e}\nWarning: you may need to remove files ending in .tmp.denc");
                    return Err(());
                }
            }
        }
    };
}
