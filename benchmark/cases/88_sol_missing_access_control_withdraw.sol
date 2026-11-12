pragma solidity ^0.8.20;
contract Treasury {
    function drainTreasury(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }
}
