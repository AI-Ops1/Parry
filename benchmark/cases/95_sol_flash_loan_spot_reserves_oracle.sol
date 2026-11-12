pragma solidity ^0.8.20;
interface IUniswapV2Pair { function getReserves() external view returns (uint112, uint112, uint32); }
contract LendingPool {
    function getCollateralPrice(address pair) external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = IUniswapV2Pair(pair).getReserves();
        return uint256(r1) / uint256(r0);
    }
}
