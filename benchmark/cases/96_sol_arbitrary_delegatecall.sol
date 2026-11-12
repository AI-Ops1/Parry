pragma solidity ^0.8.20;
contract Proxy {
    function forward(address target, bytes memory data) external {
        (bool success, ) = target.delegatecall(data);
        require(success);
    }
}
