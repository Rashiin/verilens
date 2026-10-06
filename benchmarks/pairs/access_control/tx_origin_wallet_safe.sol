// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TreasuryWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdrawAll(address payable to) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }
}
