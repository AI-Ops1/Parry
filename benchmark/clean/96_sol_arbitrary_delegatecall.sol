pragma solidity ^0.8.20;
contract Proxy {
    address public immutable implementation;
    constructor(address impl) { implementation = impl; }
    function forward(bytes memory data) external {
        (bool success, ) = implementation.delegatecall(data);
        require(success);
    }
}
