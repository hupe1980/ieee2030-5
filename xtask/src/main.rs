use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_none_or(|cmd| cmd != "codegen") {
        eprintln!("Usage: cargo xtask codegen --schema PATH [--check]");
        return ExitCode::FAILURE;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    match Command::new("python3")
        .current_dir(root)
        .arg("xtask/codegen.py")
        .args(&args[1..])
        .status()
    {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("Could not start Python 3: {e}");
            ExitCode::FAILURE
        }
    }
}
