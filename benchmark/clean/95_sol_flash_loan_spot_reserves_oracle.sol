pragma solidity ^0.8.20;
interface IChainlinkFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract LendingPool {
    function getCollateralPrice(IChainlinkFeed feed) external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(price > 0 && block.timestamp - updatedAt < 3600, "Stale price");
        return uint256(price);
    }
}
