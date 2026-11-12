pragma solidity ^0.8.20;
contract Distributor {
    function pay(address to, uint256 val) external {
        to.call{value: val}("");
    }
}
