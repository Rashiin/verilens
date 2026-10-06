// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ClosableEscrow {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function close() external {
        selfdestruct(payable(msg.sender)); // @vuln access_control
    }
}
