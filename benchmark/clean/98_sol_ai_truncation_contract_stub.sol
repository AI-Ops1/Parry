pragma solidity ^0.8.20;
contract DEXRouter {
    function swap(uint256 amountIn, uint256 minOut) external returns (uint256) {
        require(amountIn > 0 && minOut > 0, "Invalid swap");
        return minOut;
    }
}
