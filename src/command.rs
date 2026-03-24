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
    ///
    /// Parse and check the configuration file config, then exit. If command is supplied,
    /// doas will also perform command matching. In the latter case either ‘permit’,
    /// ‘permit nopass’ or ‘deny’ will be printed on standard output, depending on
    /// command matching results. No command is executed.
    #[arg(short = 'C')]
    #[arg(long_help)]
    #[arg(verbatim_doc_comment)]
    pub config: Option<String>,

    /// User name or uid
    ///
    /// Execute the command as user. The default is root.
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Non interactive mode, fail if the matching rule doesn't have the nopass option.
    #[arg(short = 'n')]
    pub non_interactive: bool,

    /// Execute the shell from SHELL or /etc/passwd.
    #[arg(short = 's', conflicts_with = "command")]
    pub shell: bool,

    /// Clear any persisted authentications from previous invocations, then immediately
    /// exit. No command is executed.
    #[arg(long_help)]
    #[arg(verbatim_doc_comment)]
    #[arg(short = 'L', conflicts_with = "command")]
    pub clear: bool,

    /// Command to run
    #[arg(
        required_unless_present = "clear",
        required_unless_present = "shell",
        required_unless_present = "config"
    )]
    pub command: Vec<OsString>,
}
