use guests::lsag_verifier::lsag_verifier::verify_b64_lsag;
use risc0_zkvm::guest::env;
fn main() {
    let input: String = env::read();
    let result = verify_b64_lsag(input.clone());
    assert!(result != None, "ring signature verification failed");
    env::commit_slice(&result.unwrap());
}
