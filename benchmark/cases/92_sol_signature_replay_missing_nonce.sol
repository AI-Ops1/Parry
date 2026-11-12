pragma solidity ^0.8.20;
contract SignerVault {
    function execute(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0));
    }
}
