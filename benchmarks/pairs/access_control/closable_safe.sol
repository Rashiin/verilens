// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ClosableEscrow {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function close() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}
