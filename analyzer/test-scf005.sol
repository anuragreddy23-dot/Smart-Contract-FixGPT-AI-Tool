pragma solidity ^0.8.20;

contract VulnerableDoS {
    uint256[] public users;

    function processUsers() external {
        for (uint256 i = 0; i < users.length; i++) {
            users[i] = users[i] + 1;
        }
    }
}