// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Crowdfund {
    address public immutable creator;
    address[] public backers;
    mapping(address => uint256) public contributed;
    bool public failed;

    constructor() {
        creator = msg.sender;
    }

    function contribute() external payable {
        if (contributed[msg.sender] == 0) {
            backers.push(msg.sender);
        }
        contributed[msg.sender] += msg.value;
    }

    function markFailed() external {
        require(msg.sender == creator, "not creator");
        failed = true;
    }

    function refundAll() external {
        require(failed, "campaign active");
        for (uint256 i = 0; i < backers.length; i++) {
            address backer = backers[i];
            uint256 amount = contributed[backer];
            contributed[backer] = 0;
            payable(backer).transfer(amount); // @vuln denial_of_service
        }
    }
}
