// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AdminRegistry {
    address public admin;
    mapping(address => bool) public verified;

    constructor() {
        admin = msg.sender;
    }

    function _requireAdmin() internal view {
        require(msg.sender == admin, "not admin");
    }

    function setVerified(address account, bool status) external {
        _requireAdmin();
        verified[account] = status;
    }

    function transferAdmin(address newAdmin) external {
        admin = newAdmin; // @vuln access_control
    }
}
