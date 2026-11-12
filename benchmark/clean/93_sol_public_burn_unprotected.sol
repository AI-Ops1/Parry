pragma solidity ^0.8.20;
contract Token {
    mapping(address => uint256) public balance;
    function burn(uint256 amount) external {
        balance[msg.sender] -= amount;
    }
}
