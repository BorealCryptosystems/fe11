// SPDX-License-Identifier: Apache-2.0
use crate::report::{self, SCENARIOS};
use std::{
    env, fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn dispatch() -> Result<(), ()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.is_empty() {
        return parent();
    }
    if args.len() == 2
        && args[0] == "--scenario"
        && SCENARIOS.contains(&args[1].as_str())
        && env::var("FE11_CI_CHILD").as_deref() == Ok("1")
    {
        return child(&args[1]);
    }
    eprintln!("invalid_arguments");
    Err(())
}

fn parent() -> Result<(), ()> {
    let root = PathBuf::from(env::var_os("FE11_CI_ROOT").ok_or(())?);
    if !root.is_absolute() || !root.is_dir() {
        return Err(());
    }
    let mut summary = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("results.tsv"))
        .map_err(|_| ())?;
    summary
        .write_all(report::HEADER.as_bytes())
        .map_err(|_| ())?;
    let deadline = Instant::now();
    let github = env::var("GITHUB_ACTIONS").as_deref() == Ok("true");
    let mut failed = false;
    for id in SCENARIOS {
        let mut process = Command::new(env::current_exe().map_err(|_| ())?)
            .args(["--scenario", id])
            .env("FE11_CI_CHILD", "1")
            .stdin(Stdio::null())
            .spawn()
            .map_err(|_| ())?;
        let exit = loop {
            match process.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if github || deadline.elapsed() < Duration::from_secs(3600) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    let _ = process.kill();
                    let _ = process.wait();
                    return Err(());
                }
            }
        };
        let row = report::read(&root.join(format!("{id}.tsv")), id);
        match row {
            Ok(row) => {
                failed |= !exit.success() || row.split('\t').nth(1) != Some("PASS");
                summary.write_all(row.as_bytes()).map_err(|_| ())?;
                summary.flush().map_err(|_| ())?;
                print!("{row}");
            }
            Err(()) => {
                failed = true;
                eprintln!("{id}: missing_or_invalid_result");
            }
        }
    }
    if failed {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn child(id: &str) -> Result<(), ()> {
    use crate::{
        environment::Environment,
        fixture::Fixture,
        report::{Cause, Failure},
    };
    let root = PathBuf::from(env::var_os("FE11_CI_ROOT").ok_or(())?);
    let mut fixture = Fixture::new();
    let operation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let environment = Environment::prepare(id)?;
        fixture.open(environment)?;
        crate::scenarios::run(id, &mut fixture)
    }))
    .unwrap_or(Err(Failure::new(Cause::Panic)));
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.cleanup()))
        .unwrap_or(Err(Failure::new(Cause::Panic)));
    let row = report::encode(id, operation, cleanup);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{id}.tsv")))
        .map_err(|_| ())?;
    file.write_all(row.as_bytes()).map_err(|_| ())?;
    if operation.is_ok() && cleanup.is_ok() {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(target_os = "linux"))]
fn child(_: &str) -> Result<(), ()> {
    eprintln!("linux_required");
    Err(())
}
