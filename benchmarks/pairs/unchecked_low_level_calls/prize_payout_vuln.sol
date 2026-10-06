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
        winner.send(address(this).balance); // @vuln unchecked_low_level_calls
        paid = true;
    }
}
