//! Filesystem probe used by Windows AppContainer ACL proofs.
//!
//! A lone `;` argument separates ops. They run in order in this one process and
//! stop at the first failure, so a proof can replay a multi-step protocol (Git's
//! lock-file dance) inside a single confined child.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for op in args.split(|arg| arg == ";") {
        if let Err(error) = run(op) {
            eprintln!("ab-fsprobe: {error}");
            std::process::exit(5);
        }
    }
}

fn run(args: &[String]) -> std::io::Result<()> {
    match args.first().map(String::as_str) {
        Some("write") if args.len() == 3 => write_file(&args[1], &args[2]),
        Some("write-sleep-write") if args.len() == 6 => {
            let sleep_ms = match args[3].parse::<u64>() {
                Ok(ms) => ms,
                Err(error) => {
                    eprintln!("invalid sleep_ms {:?}: {error}", args[3]);
                    std::process::exit(2);
                }
            };
            write_file(&args[1], &args[2]).and_then(|()| {
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                write_file(&args[4], &args[5])
            })
        }
        // On Windows this is MoveFileExW(MOVEFILE_REPLACE_EXISTING): an existing
        // target is replaced, as when Git commits index.lock over index.
        Some("rename") if args.len() == 3 => std::fs::rename(&args[1], &args[2]),
        Some("remove") if args.len() == 2 => std::fs::remove_file(&args[1]),
        Some("rmdir") if args.len() == 2 => std::fs::remove_dir(&args[1]),
        _ => {
            eprintln!(
                "usage: ab-fsprobe <op> [; <op>]... where <op> is \
                 write <path> <contents> | \
                 write-sleep-write <start-path> <start-contents> <sleep-ms> \
                 <end-path> <end-contents> | \
                 rename <from> <to> | remove <file> | rmdir <dir>"
            );
            std::process::exit(2);
        }
    }
}

fn write_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}
