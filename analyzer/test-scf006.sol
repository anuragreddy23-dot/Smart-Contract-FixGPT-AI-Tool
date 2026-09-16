pragma solidity ^0.8.20;

contract WeakRandomness {
    function random() external view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.number
                )
            )
        );
    }
}