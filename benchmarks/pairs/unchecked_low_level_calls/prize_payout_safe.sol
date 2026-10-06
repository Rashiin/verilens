pragma solidity ^0.4.24;

contract PrizePayout {
    address public organizer;
    address public winner;
    bool public paid;

    constructor(address _winner) public payable {
        organizer = msg.sender;
        winner = _winner;
    }

    function payWinner() public {
        require(!paid);
        paid = true;
        require(winner.send(address(this).balance));
    }
}
