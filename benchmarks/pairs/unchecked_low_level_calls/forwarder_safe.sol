// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Forwarder {
    address public immutable owner;
    uint256 public forwarded;

    constructor() {
        owner = msg.sender;
    }

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        (bool success, bytes memory result) = target.call(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        forwarded += 1;
        return result;
    }
}
