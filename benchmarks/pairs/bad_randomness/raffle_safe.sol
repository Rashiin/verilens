// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRandomnessOracle {
    function requestRandomness() external returns (uint256 requestId);
}

contract Raffle {
    address[] public players;
    uint256 public constant TICKET = 0.1 ether;
    IRandomnessOracle public immutable oracle;
    uint256 public pendingRequest;

    constructor(IRandomnessOracle _oracle) {
        oracle = _oracle;
    }

    function enter() external payable {
        require(pendingRequest == 0, "draw in progress");
        require(msg.value == TICKET, "wrong price");
        players.push(msg.sender);
    }

    function draw() external {
        require(players.length >= 2, "not enough players");
        require(pendingRequest == 0, "draw in progress");
        pendingRequest = oracle.requestRandomness();
    }

    function fulfillRandomness(uint256 requestId, uint256 randomness) external {
        require(msg.sender == address(oracle), "only oracle");
        require(requestId == pendingRequest, "unknown request");
        pendingRequest = 0;
        address winner = players[randomness % players.length];
        delete players;
        (bool ok, ) = payable(winner).call{value: address(this).balance}("");
        require(ok, "payout failed");
    }
}
