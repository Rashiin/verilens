// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract KingAuction {
    address public leader;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (leader != address(0)) {
            pendingReturns[leader] += highestBid;
        }
        leader = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingReturns[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}
