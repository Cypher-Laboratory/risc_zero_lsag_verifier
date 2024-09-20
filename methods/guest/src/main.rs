use lsag_verifier::lsag_verifier::verify_b64_lsag;
use risc0_zkvm::guest::env;

fn main() {
    // TODO: Implement your guest code here

    let start = env::cycle_count();
    // read the input
    let input: String = env::read();
    dbg!(&input);
    let result = verify_b64_lsag(input.clone());
    dbg!(&result);
    if result == false {
        panic!("ring signature is not valid")
    }
    dbg!("comminting to env");
    // write public output to the journal
    env::commit(&result);
    dbg!("env commited");
    let end = env::cycle_count();
    eprintln!("my_operation_to_measure: {}", end - start);
}
