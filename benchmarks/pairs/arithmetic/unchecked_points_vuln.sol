// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardPoints {
    mapping(address => uint256) public points;
    address public immutable issuer;

    constructor() {
        issuer = msg.sender;
    }

    function award(address user, uint256 amount) external {
        require(msg.sender == issuer, "not issuer");
        points[user] += amount;
    }

    function redeem(uint256 amount) external {
        unchecked {
            points[msg.sender] -= amount; // @vuln arithmetic
        }
    }
}
