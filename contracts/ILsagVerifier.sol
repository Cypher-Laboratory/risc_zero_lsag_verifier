// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ILsagVerifier {
    struct Point {
        uint256 x;
        uint256 y;
    }

    struct RingSignatureData {
        string message;
        string linkabilityFlag;
        Point keyImage;
        Point[] ring;
    }

    // verify a lsag
    function verifyRs(
        bytes calldata seal,
        bytes calldata journal,
        RingSignatureData memory _ringSignatureData
    ) external view returns (RingSignatureData memory);
}
