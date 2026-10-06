// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function deposit() external payable {
        shares[msg.sender] += msg.value;
        totalShares += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient shares");
        (bool ok, ) = payable(msg.sender).call{value: amount}(""); // @vuln reentrancy
        require(ok, "transfer failed");
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }
}
