pragma solidity ^0.8.20;

contract VulnerableReentrancy {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        (bool success, ) = msg.sender.call{value: amount}("");

        require(success);

        balances[msg.sender] = 0;
    }
}