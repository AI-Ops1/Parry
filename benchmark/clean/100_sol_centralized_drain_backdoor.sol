pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/Ownable.sol";
contract StakingPool is Ownable {
    constructor() Ownable(msg.sender) {}
    function emergencyDrain(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }
}
