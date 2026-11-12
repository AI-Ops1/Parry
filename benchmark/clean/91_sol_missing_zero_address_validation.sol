pragma solidity ^0.8.20;
contract Governed {
    address public admin;
    function setAdmin(address newAdmin) external {
        require(newAdmin != address(0), "Zero address");
        admin = newAdmin;
    }
}
