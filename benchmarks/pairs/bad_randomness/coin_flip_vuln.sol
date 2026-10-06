// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CoinFlip {
    uint256 public constant STAKE = 1 ether;

    receive() external payable {}

    function flip(bool guess) external payable {
        require(msg.value == STAKE, "wrong stake");
        bool side = uint256(blockhash(block.number - 1)) % 2 == 1; // @vuln bad_randomness
        if (side == guess) {
            (bool ok, ) = payable(msg.sender).call{value: 2 * STAKE}("");
            require(ok, "payout failed");
        }
    }
}
