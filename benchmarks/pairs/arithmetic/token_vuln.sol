// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract SimpleToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(uint256 supply) {
        balances[msg.sender] = supply;
        totalSupply = supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount; // @vuln arithmetic
        balances[to] += amount;
        return true;
    }
}
