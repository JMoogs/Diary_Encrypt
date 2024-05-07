use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase verbosity of the command
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Commands that solely encrypt data
    Encrypt {},
    /// Commands that solely decrypt data
    Decrypt {},
    /// Commands that additionally use git
    Git {},
}

#[derive(Args)]
#[group(multiple = false)]
struct PasswordOptions {
    /// Read the password from the given environment variable
    #[arg(long)]
    password_env: String,
    /// Read the password from the given file
    #[arg(long)]
    password_file: String,
    /// Provide the password as an argument
    #[arg(long)]
    password: String,
}
