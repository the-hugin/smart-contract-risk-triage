interface IERC20V12 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract MockPoolManagerV12 {
    function take(IERC20V12 currency, address to, uint256 amount) external {
        currency.transfer(to, amount);
    }
}
