// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HashPuzzle {
    bytes32 public immutable answerHash;
    bool public solved;
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public committedAt;

    constructor(bytes32 _answerHash) payable {
        answerHash = _answerHash;
    }

    function commit(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        committedAt[msg.sender] = block.number;
    }

    function reveal(string calldata solution, bytes32 salt) external {
        require(!solved, "already solved");
        require(committedAt[msg.sender] != 0 && committedAt[msg.sender] < block.number, "commit first");
        require(keccak256(abi.encodePacked(msg.sender, solution, salt)) == commitments[msg.sender], "bad reveal");
        require(keccak256(abi.encodePacked(solution)) == answerHash, "wrong answer");
        solved = true;
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "payout failed");
    }
}
