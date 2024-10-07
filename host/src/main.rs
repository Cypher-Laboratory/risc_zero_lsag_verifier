// The ELF is used for proving and the ID is uuse std::fs::File;
use chrono::Utc;
use methods::{LSAG_VERIFIER_ELF, LSAG_VERIFIER_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::fs::File;
use std::io::Write;

fn main() -> std::io::Result<()> {
    let start_time = Utc::now();

    //rs with keccak
    //let input = "eyJtZXNzYWdlIjoibWVzc2FnZSIsInJpbmciOlsiMDIwOGY0ZjM3ZTJkOGY3NGUxOGMxYjhmZGUyMzc0ZDVmMjg0MDJmYjhhYjdmZDFjYzViNzg2YWE0MDg1MWE3MGNiIiwiMDMxNmQ3ZGE3MGJhMjQ3YTZhNDBiYjMxMDE4N2U4Nzg5YjgwYzQ1ZmE2ZGMwMDYxYWJiOGNlZDQ5Y2JlN2Y4ODdmIiwiMDIyMTg2OWNhM2FlMzNiZTNhNzMyN2U5YTAyNzIyMDNhZmE3MmM1MmE1NDYwY2ViOWY0YTUwOTMwNTMxYmQ5MjZhIiwiMDIzMzdkNmY1NzdlNjZhMjFhNzgzMWMwODdjNjgzNmExYmFlMzcwODZiZjQzMTQwMDgxMWFjN2M2ZTk2YzhjY2JiIl0sImMiOiI4NjM3OWI0Mzg2MWU5NTBiNWZhNGI3NTcxYWZmMGM2MDA0NTc4ZTcxMjgwYWFlZGI5OTM4MzNjOWJkZTYzYzQzIiwicmVzcG9uc2VzIjpbImQ2YzE4NTRlZWIxMzJkNTg4NmFjNTkwYzUzMGE1NWE3ZmJhM2Q5MmM0ZWI2ODk2YTcyOGIwYTYxODk5YWQ5MDIiLCI2YTUxZDczMWIzOTgwMzZlZDNiM2I1Y2ZkMjA2NDA3YTM1ZmQxMWZhYTJiYmFkMTY1OGJjZjlmMDhiOWM1ZmI4IiwiNmE1MWQ3MzFiMzk4MDM2ZWQzYjNiNWNmZDIwNjQwN2EzNWZkMTFmYWEyYmJhZDE2NThiY2Y5ZjA4YjljNWZiOCIsIjZhNTFkNzMxYjM5ODAzNmVkM2IzYjVjZmQyMDY0MDdhMzVmZDExZmFhMmJiYWQxNjU4YmNmOWYwOGI5YzVmYjgiXSwiY3VydmUiOiJ7XCJjdXJ2ZVwiOlwiU0VDUDI1NksxXCJ9Iiwia2V5SW1hZ2UiOiIwMjE5MWViOWYwNjM2YTViMWE4N2VkNjZjYzAwZDViM2ZmYTM1ZDRlMDRjNGIyMWM4ZTQ4ZGI5ODdhYmI2MDBiMTEiLCJsaW5rYWJpbGl0eUZsYWciOiJsaW5rYWJpbGl0eSBmbGFnIiwiZXZtV2l0bmVzc2VzIjpbXX0=";

    let input = "eyJtZXNzYWdlIjoiSGVsbG8gV29ybGQiLCJyaW5nIjpbIjAyMjE4NjljYTNhZTMzYmUzYTczMjdlOWEwMjcyMjAzYWZhNzJjNTJhNTQ2MGNlYjlmNGE1MDkzMDUzMWJkOTI2YSIsIjAzNDI4ZTAyMGYxODRiNzBjYTkzMWE5MTA4NWFjMWMyMzM4MjdhNDFkODUxNmE0YjY0NTVlMjIxZTYzN2M0ZGUwZiIsIjAzNDM4ZmJmMzc3NmNjMjRlMjUzNTgyMjU0NGYxNGQ3YjA1N2Q4OTU3YzcyNjc2MDE4MDA1MmNkYTdiOGJhNmM4MyIsIjAzNTBjMWJkNjRjMzA4N2Y2NWY0ODE3MTdlZTRhNWJkZmJiYTRmMDYwMzE0OTkzZjFlMTVjMGRiMjk3NDhiOGRjMiJdLCJjIjoiM2M3ZDBhYzE4YjBlYWU4N2M1OTFjMGM5ZWRkOWE3ZDU3YjI5ZWUxZDhiNzZlYTFjOGM1NjAxMDQ3MGMwZDViMiIsInJlc3BvbnNlcyI6WyIxOWUzNGNjOTc5Y2E1YWMzYTk2MThkMGNlZThmYjdmNzRlMmY4MzA5MmY2ZDZmOTUyZTA3OWYxMzY1MmNlNjM2IiwiYjRkZGE5ZTc4YzA4OTliYjFjYmNkYTVjMjhiYWRiZjYwYWIzMDc1N2MyZjVhMWIxNWQwZDliNmQ1MzdhMTMwMSIsIjJhY2Q4ZWIzMzZhZjU5YzIwMTVhNDljMGJlMWZhZmE3Yzk0ODRmYWQ4YmY3MmFmYjZjYmIwYzgzMDhhOGUxODUiLCI1Y2IzNWY3OWVmYzBmODEwYTI0NTMxYjU0YWM0NThiNjZkMTZlNzNhMTdjOWEyY2IxYTkyN2QzYzI1YTNkMDY4Il0sImN1cnZlIjoie1wiY3VydmVcIjpcIlNFQ1AyNTZLMVwifSIsImtleUltYWdlIjoiMDJlN2ZmMzQ5MGVlN2RiMzM3NTBmZTlhNzA5MWQ4MmRjYTk1MmU2ZDIyYTdmZDRkZjk3ZDBjYmY4ZjdjYjQ2YWQyIiwibGlua2FiaWxpdHlGbGFnIjoibGlua2FiaWxpdHkiLCJjb25maWciOnsiaGFzaCI6InNoYTI1NiJ9fQ==";
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let prove_info = prover.prove(env, LSAG_VERIFIER_ELF).unwrap();
    let receipt = prove_info.receipt;

    let output: [u8; 32] = receipt.journal.decode().unwrap();
    dbg!(&output);
    let verification = receipt.verify(LSAG_VERIFIER_ID).unwrap();

    let end_time = Utc::now();
    let duration = end_time.signed_duration_since(start_time);

    // Create a new file named "output.txt"
    let mut file = File::create("output.txt")?;

    // Write the output, verification results, and execution time to the file
    writeln!(file, "Output: {:?}", output)?;
    writeln!(file, "Verification: {:?}", verification)?;
    writeln!(
        file,
        "Execution time: {} milliseconds",
        duration.num_milliseconds()
    )?;
    writeln!(file, "Receipt: {:?}", receipt)?;

    println!("Results have been written to output.txt");
    println!(
        "Execution time: {} milliseconds",
        duration.num_milliseconds()
    );

    Ok(())
}
