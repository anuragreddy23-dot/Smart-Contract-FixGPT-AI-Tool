pragma solidity ^0.8.20;

contract ZeroAddressSecure {
    address public owner;

    function setOwner(address newOwner) external {
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }
}