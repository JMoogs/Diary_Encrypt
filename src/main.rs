mod cli;

use clap::Parser;
use cli::{Cli, EncryptDecryptOptions, PasswordOptions};
use rpassword;
use std::process::{self, Command};
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
    let pass = match get_pass(c.pass_option) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to get a password: {e}");
            return;
        }
    };
}

fn get_pass(opts: PasswordOptions) -> Result<String, EncryptError> {
    // Read from the environment variable
    if let Some(env) = opts.password_env {
        if let Ok(pass) = std::env::var(env) {
            Ok(pass)
        } else {
            return Err(EncryptError::EnvVarError);
        }
    // Read from a file
    } else if let Some(file) = opts.password_file {
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
        if atty::is(atty::Stream::Stdin) {
            // Stdin isn't redirected so no pipe
            if let Ok(pass) = rpassword::prompt_password("Enter password: ") {
                return Ok(pass);
            } else {
                return Err(EncryptError::PromptError);
            }
        } else {
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
    output_file: Option<String>,
) -> Result<(), ()> {
    match output_file {
        Some(out_file) => {
            let status = Command::new("gpg")
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
                .status();

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
