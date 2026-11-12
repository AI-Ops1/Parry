pragma solidity ^0.8.20;
import "@openzeppelin/contracts/math/SafeMath.sol";
contract Calculator {
    using SafeMath for uint256;
    function add(uint256 a, uint256 b) external pure returns (uint256) { return a.add(b); }
}
