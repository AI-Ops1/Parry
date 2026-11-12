pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool s, ) = msg.sender.call{value: amount}("");
        require(s);
        balances[msg.sender] -= amount;
    }
}
