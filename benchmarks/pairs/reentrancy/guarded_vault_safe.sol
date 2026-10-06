// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    bool private entered;

    modifier guarded() {
        require(!entered, "reentrant call");
        entered = true;
        _;
        entered = false;
    }

    function deposit() external payable guarded {
        shares[msg.sender] += msg.value;
        totalShares += msg.value;
    }

    function withdraw(uint256 amount) external guarded {
        require(shares[msg.sender] >= amount, "insufficient shares");
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }
}
