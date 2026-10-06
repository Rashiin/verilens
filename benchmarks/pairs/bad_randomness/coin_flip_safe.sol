// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CoinFlip {
    uint256 public constant STAKE = 1 ether;
    address public playerA;
    address public playerB;
    bytes32 public commitA;
    bytes32 public commitB;
    bytes32 private secretA;
    bytes32 private secretB;
    bool public revealedA;
    bool public revealedB;

    function join(bytes32 commitment) external payable {
        require(msg.value == STAKE, "wrong stake");
        if (playerA == address(0)) {
            playerA = msg.sender;
            commitA = commitment;
        } else {
            require(playerB == address(0), "game full");
            playerB = msg.sender;
            commitB = commitment;
        }
    }

    function reveal(bytes32 secret) external {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, secret));
        if (msg.sender == playerA && h == commitA) {
            secretA = secret;
            revealedA = true;
        } else if (msg.sender == playerB && h == commitB) {
            secretB = secret;
            revealedB = true;
        } else {
            revert("invalid reveal");
        }
    }

    function settle() external {
        require(revealedA && revealedB, "not revealed");
        bool aWins = uint256(keccak256(abi.encodePacked(secretA, secretB))) % 2 == 0;
        address winner = aWins ? playerA : playerB;
        revealedA = false;
        revealedB = false;
        (bool ok, ) = payable(winner).call{value: address(this).balance}("");
        require(ok, "payout failed");
    }
}
