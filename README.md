# RISC Zero LSAG Verifier

> Verify Linkable Spontaneous Anonymous Group (LSAG) signatures using RISC Zero zkVM as an EVM coprocessor.

This repository implements an LSAG signature verification system on EVM utilizing RISC Zero as a coprocessor to the smart contract application. It provides a solution for verifying ring signatures in a gas-efficient manner by offloading the computationally intensive verification process to RISC Zero's zkVM.

## Overview

Here is a simplified overview of how the LSAG verification works with RISC Zero and Bonsai proving:

1. The LSAG signature and ring member public keys are processed in the RISC Zero zkVM. The publisher app sends an off-chain proof request to the Bonsai proving service.
2. Bonsai generates the verification result, written to the journal, and a SNARK proof of its correctness.
3. The publisher app submits this proof and journal on-chain to your app contract for validation.
4. Your app contract calls the RISC Zero Verifier to validate the proof. If the verification is successful, the LSAG signature is deemed valid and can be safely used.

## Dependencies

First, install Rust and Foundry, and then restart your terminal.

```sh
# Install Rust
curl https://sh.rustup.rs -sSf | sh
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
```

Next, install the RISC Zero toolchain:

```sh
# Install rzup
curl -L https://risczero.com/install | bash

# Install RISC Zero toolchain
rzup

# Verify installation
cargo risczero --version
```

## Quick Start
After installing the dependencies, you can clone and set up the project:

```sh
# Clone the repository
git clone https://github.com/Cypher-Laboratory/risc_zero_lsag_verifier.git
cd risc_zero_lsag_verifier

# Build the Solidity contracts
forge build

# Build the Rust components
cargo build
```

## Project Components

The LSAG verifier consists of three main components:

### 1. Guest Code (RISC Zero zkVM Program)
Located in [methods/guest](./methods/guest/), this code implements the LSAG signature verification algorithm. It:
- Validates the ring signature structure
- Performs the cryptographic verification steps 
- Outputs the verification result to the journal

### 2. Smart Contracts
Located in [contracts](./contracts/), the smart contracts:
- Receive LSAG signatures, ring member public keys and the Groth16 proof
- Verify RISC Zero proof of signature verification
- Verifies on-chain data integrity by comparing the receipt's stored hash against the hash of provided signature data

### 3. Publisher Application
Located in [apps](./apps/), the publisher:
- Accepts LSAG signatures for verification
- Submits proof requests to Bonsai
- Posts verification results and proofs to the smart contract

  ## Usage

This project provides a boilerplate for LSAG signature verification that can be adapted to various use cases (CLI, backend services, APIs, etc.).

### Overall Process

1. **Signature Creation**
  - Using TypeScript LSAG [implementation](https://docs.alicesring.org/docs/LSAG/LSAG-ts) in your frontend/application
  - Generate a ring signature
  - Encode the resulting signature in base64 format

2. **Verification Request**
  - Pass the base64-encoded signature to the verification service
  - Provider either via CLI interface or any other integration point
  - Include the ring members' public keys along with the signature

3. **Result Processing**
  - The system verifies the signature via RISC Zero
  - Returns proof of valid/invalid signature
  - Results can be verified on-chain and then used for further application logic

### Integration Notes
While this example uses a CLI approach, the verification process is designed to be flexible and can be integrated into:
- Web backends
- REST APIs
- Blockchain indexers
- Smart contract systems
- Custom applications

The core verification logic remains consistent regardless of the integration method, allowing for versatile implementation approaches. 

## Deployed Addresses

| Network       | Contract          | Address                                      |
|--------------|-------------------|----------------------------------------------|
| Polygon Amoy | RiscZeroVerifier | 0xD1b512E8d5e80FC52E7609FA70D6068608DA02EF |
| Polygon Amoy | LSAGVerifier     | 0x43992dC1dec1D4B7936f3c84D8E48e4C09a08513 |
