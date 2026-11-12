pragma solidity ^0.8.20;
contract Lottery {
    function pickWinner(uint256 players) external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % players;
    }
}
