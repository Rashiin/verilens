// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Raffle {
    address[] public players;
    uint256 public constant TICKET = 0.1 ether;

    function enter() external payable {
        require(msg.value == TICKET, "wrong price");
        players.push(msg.sender);
    }

    function draw() external {
        require(players.length >= 2, "not enough players");
        uint256 index = uint256(keccak256(abi.encodePacked(block.prevrandao, block.timestamp, players.length))) % players.length; // @vuln bad_randomness
        address winner = players[index];
        delete players;
        (bool ok, ) = payable(winner).call{value: address(this).balance}("");
        require(ok, "payout failed");
    }
}
