pragma solidity ^0.8.20;

contract ProxyStorage {
    address public implementation;

    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }
}

contract NewImplementation {
    uint256 public implementation;

    function upgrade(address newImplementation) external {
        newImplementation.delegatecall("");
    }
}