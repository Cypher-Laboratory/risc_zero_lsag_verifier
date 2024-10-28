// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.

contract LsagVerifier {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public constant imageId = ImageID.LSAG_VERIFIER_ID;

    struct Point {
        uint256 x;
        uint256 y;
    }

    struct RingSignatureData {
        Point[] ring;
        string message;
        string keyImage;
        string linkabilityFlag;
    }

    //tempo struct use for the proto
    //only use the x coord when checking the sanity of the
    struct PartialRingSignatureData {
        string message;
        string linkabilityFlag;
        uint256 keyImage;
        uint256[] ring;
    }

    constructor(IRiscZeroVerifier _verifierAddress) {
        verifier = _verifierAddress;
    }

    // verify a linkeable ring sinature
    // It check if the Groth16 proof from risc zero is valid
    // If valid it check by hashing that the ringSignature data are the one from the digest
    // the receipt is composed as the following :
    // receipt : sha256(_ringSignatureData)
    // if the signature is valid, it returns the ringSignature data passed as argument
    function verifyRs(
        bytes calldata seal,
        bytes calldata journal,
        RingSignatureData memory _ringSignatureData
    ) external view returns (RingSignatureData memory) {
        verifier.verify(seal, imageId, sha256(journal));
        //decode the journal
        bytes32 hash_ring_sig_data = bytes32(journal[0:32]);
        //ensure that the ring signature data are the one that have been used on risc zero
        if (hash_ring_sig_data != sha256(abi.encode(_ringSignatureData))) {
            revert("Journal hash and ring signature data digest doesn't match");
        }
        //the data is trusted, you can implem your own logic here
        return _ringSignatureData;
    }

    // verify a LSAG
    // tempo function, the verification of the ring is only based on the X-coord
    function partialLsagVerification(
        bytes calldata seal,
        bytes calldata journal,
        PartialRingSignatureData memory _ringSignatureData
    ) external view returns (PartialRingSignatureData memory) {
        verifier.verify(seal, imageId, sha256(journal));
        bytes32 hash_ring_sig_data = bytes32(journal[0:32]);
        bytes32 hashed_ring_sig = sha256(abi.encode(_ringSignatureData));
        if (hash_ring_sig_data != hashed_ring_sig) {
            revert(
                "Journal hash and ring signature data digest doesn't match. Expected: 0x"
            );
        }
        //the data is trusted, you can implem your own logic here
        return _ringSignatureData;
    }
}
