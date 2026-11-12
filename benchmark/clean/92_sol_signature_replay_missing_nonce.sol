pragma solidity ^0.8.20;
contract SignerVault {
    mapping(address => uint256) public nonces;
    function execute(bytes32 message, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[msg.sender]++, "Invalid nonce");
        bytes32 hash = keccak256(abi.encodePacked(message, nonce, block.chainid));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0));
    }
}
