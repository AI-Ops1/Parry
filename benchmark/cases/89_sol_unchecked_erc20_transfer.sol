pragma solidity ^0.8.20;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
contract Payout {
    function sendToken(address token, address to, uint256 amt) external {
        IERC20(token).transfer(to, amt);
    }
}
