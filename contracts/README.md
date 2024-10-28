# Solidity Contracts for LSAG Verification

This directory contains Solidity contracts for implementing Linkable Spontaneous Anonymous Group (LSAG) signature verification on Ethereum, leveraging [RISC Zero] for secure off-chain computation.

The main contract included is [`LsagVerifier.sol`](./LsagVerifier.sol), which validates Groth16 proofs using RISC Zero and ensures that the LSAG signature data corresponds to the receipt hash provided.

The Solidity libraries for RISC Zero are available at [github.com/risc0/risc0-ethereum].

Contracts are developed and tested using [forge] from the [Foundry] toolkit. Tests are defined in the `tests` directory.

## Contract Overview

### `LsagVerifier`

The `LsagVerifier` contract includes two main functions:

1. **`verifyRs`**: Verifies a full LSAG ring signature by checking that the RISC Zero-generated proof and the journal data match the provided ring signature data. If valid, the function returns the ring signature data for further processing.

2. **`partialLsagVerification`**: A temporary verification function for LSAGs that only verifies the ring signature based on the x-coordinates of the ring points. This function also ensures the hash of the `PartialRingSignatureData` matches the journal's digest, providing a lightweight validation for specific use cases.

### Contract Structure

- `IRiscZeroVerifier`: Interface for the RISC Zero verifier used to check proof validity.
- `ImageID`: Contains auto-generated identifiers used to verify specific guest computations.

### Structs Used

- **`RingSignatureData`**: Contains the complete data for verifying an LSAG ring signature.
- **`PartialRingSignatureData`**: A simplified version used in `partialLsagVerification` to verify ring signatures based only on x-coordinates.

## Generated Contracts

This project generates specific contracts as part of the build process. Running `cargo build` will generate these contracts, updating references to guest computations as needed.

- **`ImageID.sol`**: Contains the [Image IDs][image-id] for RISC Zero's guest code used in ring signature verification.
- **`Elf.sol`**: Points to guest binary paths, supporting the verifier. This contract is located in the `tests` directory of this template.

## Getting Started

To build and test the contracts, ensure [Foundry] is installed, and use the following commands:

1. **Build**: Compile the contracts and generate image IDs with `cargo build`.
2. **Test**: Run contract tests using `forge test`.

## Resources

- [RISC Zero Documentation][RISC Zero]
- [Foundry Documentation][Foundry]
- [Alice's Ring Documentation][https://docs.alicesring.org]
- [RISC Zero Solidity Libraries][github.com/risc0/risc0-ethereum]

[Foundry]: https://getfoundry.sh/
[RISC Zero]: https://risczero.com
[forge]: https://github.com/foundry-rs/foundry#forge
[github.com/risc0/risc0-ethereum]: https://github.com/risc0/risc0-ethereum/tree/main/contracts
[image-id]: https://dev.risczero.com/terminology#image-id
