// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Forwarder {
    address public immutable owner;
    uint256 public forwarded;

    constructor() {
        owner = msg.sender;
    }

    function forward(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        target.call(data); // @vuln unchecked_low_level_calls
        forwarded += 1;
    }
}
