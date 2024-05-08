use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[command(flatten)]
    pub pass_option: PasswordOptions,
    /// Increase verbosity of the command
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Commands that solely encrypt data
    Encrypt(#[command(flatten)] EncryptDecryptOptions),
    /// Commands that solely decrypt data
    Decrypt(#[command(flatten)] EncryptDecryptOptions),
    /// Commands that additionally use git
    Git {},
}

#[derive(Args)]
#[group(required = false, multiple = false)]
pub struct PasswordOptions {
    /// Read the password from the given environment variable
    #[arg(long)]
    pub password_env: Option<String>,
    /// Read the password from the given file
    #[arg(long)]
    pub password_file: Option<String>,
    /// Provide the password as an argument
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(Args)]
pub struct EncryptDecryptOptions {
    /// An input file or directory
    #[arg(short, long)]
    pub input: String,
    #[command(flatten)]
    pub output: OutputOptions,
    /// Force encryption/decryption, bypassing any checks
    #[arg(long, short)]
    pub force: bool,
}

#[derive(Args)]
#[group(multiple = false, required = true)]
pub struct OutputOptions {
    /// The output file/directory name
    #[arg(short, long)]
    pub output: Option<String>,
    /// Replace the input file with the output file
    #[arg(short, long)]
    pub replace: bool,
}
