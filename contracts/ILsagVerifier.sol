// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ILsagVerifier {
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

    struct PartialRingSignatureData {
        string message;
        string linkabilityFlag;
        uint256 keyImage;
        uint256[] ring;
    }

    function verifyRs(
        bytes calldata seal,
        bytes calldata journal,
        RingSignatureData memory _ringSignatureData
    ) external view returns (RingSignatureData memory);

    // verify a LSAG
    // tempo function, the verification of the ring is only based on the X-coord
    function partialLsagVerification(
        bytes calldata seal,
        bytes calldata journal,
        PartialRingSignatureData memory _ringSignatureData
    ) external view returns (PartialRingSignatureData memory);
}
