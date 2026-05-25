use anyhow::Result;

use crate::utils::write_final_ip_lists_from_jsonl;

pub fn run_finalize(jsonl_file: String) -> Result<()> {
    let (alive_file, rejected_file, alive_count, rejected_count) =
        write_final_ip_lists_from_jsonl(&jsonl_file)?;
    println!("Alive IPs: {} -> {}", alive_count, alive_file);
    println!("Rejected IPs: {} -> {}", rejected_count, rejected_file);
    Ok(())
}
