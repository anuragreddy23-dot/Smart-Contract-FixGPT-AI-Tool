pragma solidity ^0.8.20;

contract SecurityTest {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }

    function upgradeTo(address implementation) external {
        (bool ok,) = implementation.delegatecall("");
    }

    function setUser(address user) external {
        owner = user;
    }

    function approveToken(address token, address spender) external {
        token.approve(spender, 100);
    }

    function getPrice(address pair) external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return uint256(reserve0) / uint256(reserve1);
    }

    function flashOperation(address lender) external {
        lender.flashLoan(address(this), 1000);
    }

    function execute(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address signer = ecrecover(
            digest,
            v,
            r,
            s
        );

        require(
            signer != address(0),
            "Invalid signature"
        );
    }

    function upgrade(address implementation) external {
        implementation.delegatecall("");
    }

    function withdraw(address payable recipient) external {
        recipient.transfer(
            address(this).balance
        );
    }
}
