pragma solidity ^0.8.20;
contract Wallet {
    address public owner;
    function transferTo(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Not authorized");
        to.transfer(amount);
    }
}
