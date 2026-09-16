pragma solidity ^0.8.20;

contract ZeroAddressTest {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}