pragma solidity ^0.8.20;
contract Governed {
    address public admin;
    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }
}
