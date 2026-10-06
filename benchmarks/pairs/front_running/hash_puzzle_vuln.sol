// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HashPuzzle {
    bytes32 public immutable answerHash;
    bool public solved;

    constructor(bytes32 _answerHash) payable {
        answerHash = _answerHash;
    }

    function solve(string calldata solution) external {
        require(!solved, "already solved");
        require(keccak256(abi.encodePacked(solution)) == answerHash, "wrong answer"); // @vuln front_running
        solved = true;
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "payout failed");
    }
}
