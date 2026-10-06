// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Crowdfund {
    address public immutable creator;
    mapping(address => uint256) public contributed;
    bool public failed;

    constructor() {
        creator = msg.sender;
    }

    function contribute() external payable {
        contributed[msg.sender] += msg.value;
    }

    function markFailed() external {
        require(msg.sender == creator, "not creator");
        failed = true;
    }

    function claimRefund() external {
        require(failed, "campaign active");
        uint256 amount = contributed[msg.sender];
        require(amount > 0, "nothing to refund");
        contributed[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "refund failed");
    }
}
