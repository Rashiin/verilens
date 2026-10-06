// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract KingAuction {
    address public leader;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (leader != address(0)) {
            payable(leader).transfer(highestBid); // @vuln denial_of_service
        }
        leader = msg.sender;
        highestBid = msg.value;
    }
}
