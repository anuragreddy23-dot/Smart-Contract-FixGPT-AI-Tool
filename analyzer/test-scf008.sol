pragma solidity ^0.8.20;

contract TxOriginAuth {
    address public owner;

    function withdraw() external {
        require(tx.origin == owner);
    }
}