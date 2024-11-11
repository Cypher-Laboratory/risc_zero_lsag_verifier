# zkVM LSAG Verifier Implementation

This directory contains the core implementation of the LSAG (Linkable Spontaneous Anonymous Group) signature verification logic for the [RISC Zero zkVM].

## Overview

The verifier is implemented using cryptographically optimized libraries specifically chosen to minimize cycle count on the zkVM. This optimization is crucial for efficient proof generation.

## Structure

- **[guest/src/bin/verifier.rs](./guest/src/bin/verifier.rs)**: Main verification logic
 - Implements LSAG signature verification algorithm
 - Uses cycle-optimized crypto primitives
 - Outputs verification results to the journal

## Implementation Notes

The verifier leverages:
- Optimized cryptographic libraries for zkVM
- Efficient curve operations
- Minimized cycle count for cost-effective verification

## Development

To modify the verification logic:
1. Edit the verification code in `guest/src/bin/lasg_verifier`
3. The build system will automatically handle binary compilation and image ID generation

For more information on zkVM development:
- [Guest Code 101]
- [RISC Zero examples]

[RISC Zero zkVM]: https://dev.risczero.com/zkvm
[Guest Code 101]: https://dev.risczero.com/zkvm/developer-guide/guest-code-101
[RISC Zero examples]: https://github.com/risc0/tree/v0.18.0/examples
