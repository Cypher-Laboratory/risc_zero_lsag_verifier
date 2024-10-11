use lsag_verifier::verify_b64_lsag;
use risc0_zkvm::guest::env;

fn main() {
    let input: String = env::read();
    let result = verify_b64_lsag(input.clone());
    if result == None {
        panic!("ring signature is not valid")
    }
    env::commit(&Some(result));
}
