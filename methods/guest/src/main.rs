use lsag_verifier::lsag_verifier::{to_minimal_lsag_digest, verify_b64_lsag};
use risc0_zkvm::guest::env;

fn main() {
    let start = env::cycle_count();
    let input: String = env::read();
    let result = verify_b64_lsag(input.clone());
    if result == None {
        panic!("ring signature is not valid")
    }
    env::commit(&Some(result));
    let end = env::cycle_count();
}
