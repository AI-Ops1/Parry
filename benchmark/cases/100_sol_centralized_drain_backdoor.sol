pragma solidity ^0.8.20;
contract StakingPool {
    function emergencyDrain(address payable to) external {
        to.transfer(address(this).balance);
    }
}
