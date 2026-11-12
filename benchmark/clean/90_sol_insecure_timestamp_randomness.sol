pragma solidity ^0.8.20;
contract Lottery {
    function fulfillRandomWords(uint256 vrfRandomWord, uint256 players) internal pure returns (uint256) {
        return vrfRandomWord % players;
    }
}
