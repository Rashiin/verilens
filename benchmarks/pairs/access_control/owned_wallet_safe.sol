pragma solidity ^0.4.24;

contract OwnedWallet {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function () public payable {}

    function withdraw(uint256 amount) public {
        require(msg.sender == owner);
        msg.sender.transfer(amount);
    }
}
