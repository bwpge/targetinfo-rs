mod output;

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use smb::Client;
use smb::ClientConfig;
use smb::Result as SMBResult;
use sspi::ntlm::GLOBAL_AV_PAIRS;

use crate::output::{Output, Record};

/// Parses AV_PAIRs from TargetInfo blocks in NTLM challenges via SMB
#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// Specified as IPv4 or 'localhost', use <TARGET>:<PORT> to specify a different port
    #[arg(required = true)]
    target: Vec<String>,

    /// Connection timeout in seconds as a floating point number
    #[arg(short, long)]
    timeout: Option<f32>,

    /// Write output in a greppable format
    #[arg(short, long)]
    greppable: bool,

    /// Disable color output (color is always disabled with -g)
    #[arg(long)]
    no_color: bool,

    /// When scanning multiple targets, prevent exiting if an error is encountered
    #[arg(short = 'C', long)]
    continue_on_error: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut cli = Cli::parse();
    let output = Output::new(cli.greppable, cli.no_color);

    let mut secs = cli.timeout.unwrap_or(3.0);
    if secs <= 0.0 {
        output.warn(format!("'{secs}' is not a valid timeout, using 3s"));
        secs = 3.0;
    }
    cli.timeout = Some(secs);

    for target in &cli.target {
        match run(target, &cli, &output).await {
            Ok(_) => (),
            Err(e) => {
                output.error(e);
                if !cli.continue_on_error {
                    return ExitCode::FAILURE;
                }
            }
        };
    }

    ExitCode::SUCCESS
}

async fn run(target: &str, cli: &Cli, output: &Output) -> SMBResult<()> {
    output.print_header(target);
    let timeout = cli.timeout.unwrap_or(3.0);

    let mut try_smb2_only = false;
    match do_connect(target, timeout, false).await {
        Ok(_) => (),
        Err(e) => {
            match e {
                // we get an invalid message error when servers don't negotiate correctly. this can
                // happen on older servers that don't negotiate multi-protocol
                smb::Error::InvalidMessage(_) => try_smb2_only = true,
                _ => return Err(e),
            };
        }
    };

    if try_smb2_only {
        do_connect(target, timeout, true).await?;
    }

    let pairs = GLOBAL_AV_PAIRS.lock().unwrap();
    output.print(Record::new(target, pairs.clone()));

    Ok(())
}

async fn do_connect(target: &str, timeout: f32, smb2_only: bool) -> SMBResult<()> {
    let mut conf = ClientConfig::default();
    conf.connection.timeout = Some(Duration::from_secs_f32(timeout));
    if smb2_only {
        conf.connection.smb2_only_negotiate = true;
    }
    let client = Client::new(conf.clone());

    // credentials are never actually used
    let user = "asdf";
    let password = String::from(user);

    // this is always going to be an error because of the sspi patch, so just sanity check
    // something else didn't go wrong. this is obviously not perfect if sspi runs into a different
    // error while getting the NTLM challenge
    let res = match client.ipc_connect(target, user, password).await {
        Ok(_) => Ok(()),
        Err(e) => match e {
            smb::Error::SspiError(_) => Ok(()),
            _ => Err(e),
        },
    };

    let _ = client.close().await;
    res
}
