//! Filesystem probe used by Windows AppContainer ACL proofs.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
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
        _ => {
            eprintln!(
                "usage: ab-fsprobe write <path> <contents> | \
                 write-sleep-write <start-path> <start-contents> <sleep-ms> \
                 <end-path> <end-contents>"
            );
            std::process::exit(2);
        }
    };

    if let Err(error) = result {
        eprintln!("ab-fsprobe: {error}");
        std::process::exit(5);
    }
}

fn write_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}
