pragma solidity ^0.8.20;

contract VulnerableArithmetic {
    uint256 public total;

    function calculate(uint256 a, uint256 b) external {
        unchecked {
            total = a + b;
        }
    }
}