use clap::Parser;
use std::ffi::OsString;

#[derive(Parser)]
#[command(
    name = "doas",
    version = "0.1.0",
    about = "A simple doas implementation",
    trailing_var_arg = true
)]
pub struct CliArgs {
    /// Config path
    #[arg(short = 'C')]
    pub config: Option<String>,

    /// Run command as user
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Do not prompt for password
    #[arg(short = 'n')]
    pub non_interactive: bool,

    /// Run a shell
    #[arg(short = 's', conflicts_with = "command")]
    pub shell: bool,

    /// Validate credentials
    #[arg(short = 'v', conflicts_with = "command")]
    pub validate: bool,

    /// Command to run
    #[arg(
        required_unless_present = "validate",
        required_unless_present = "shell",
        required_unless_present = "config"
    )]
    pub command: Vec<OsString>,
}
