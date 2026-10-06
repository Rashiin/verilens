// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BonusSale {
    mapping(address => uint256) public tokens;
    uint256 public immutable closingTime;

    constructor() {
        closingTime = block.timestamp + 30 days;
    }

    function buy() external payable {
        require(block.timestamp <= closingTime, "sale closed");
        uint256 amount = msg.value * 100;
        if (block.timestamp % 60 == 0) { // @vuln time_manipulation
            amount *= 2;
        }
        tokens[msg.sender] += amount;
    }
}
