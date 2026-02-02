use std::process::ExitCode;
use std::time::Duration;

use smb::Client;
use smb::ClientConfig;
use smb::Result as SMBResult;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 || args[1].is_empty() {
        eprintln!("target argument is required");
        return ExitCode::FAILURE;
    }

    let target = &args[1];
    match run(target).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(target: &str) -> SMBResult<()> {
    let mut conf = ClientConfig::default();
    conf.connection.timeout = Some(Duration::from_secs(1));
    let client = Client::new(conf);

    // credentials are never actually used
    let user = "asdf";
    let password = String::from(user);

    // this is always going to be an error because of the sspi patch, so just sanity check
    // something else didn't go wrong. this is obviously not perfect if sspi runs into a different
    // error while getting the NTLM challenge
    let res = client.ipc_connect(target, user, password).await;
    match res {
        Ok(_) => todo!(),
        Err(e) => {
            match e {
                smb::Error::SspiError(_) => (),
                _ => return Err(e),
            };
        }
    };

    // TODO: fix this global state nonsense
    let pairs = sspi::ntlm::GLOBAL_AV_PAIRS.lock().unwrap();
    for item in &*pairs {
        println!("{}: {}", item.id, item.value);
    }

    let _ = client.close().await;
    Ok(())
}
