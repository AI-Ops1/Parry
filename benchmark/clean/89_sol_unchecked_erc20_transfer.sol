pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
contract Payout {
    using SafeERC20 for IERC20;
    function sendToken(IERC20 token, address to, uint256 amt) external {
        token.safeTransfer(to, amt);
    }
}
