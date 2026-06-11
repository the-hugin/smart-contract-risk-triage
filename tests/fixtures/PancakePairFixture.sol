contract PancakePair {
    address public factory;
    address public token0;
    address public token1;
    uint112 private reserve0;
    uint112 private reserve1;

    modifier lock() {
        _;
    }

    function initialize(address _token0, address _token1) external {
        require(msg.sender == factory, "Pancake: FORBIDDEN");
        token0 = _token0;
        token1 = _token1;
    }

    function getReserves() public view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, 0);
    }

    function burn(address to) external lock returns (uint amount0, uint amount1) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        amount0 = _reserve0 / 10;
        amount1 = _reserve1 / 10;
        _safeTransfer(token0, to, amount0);
        _safeTransfer(token1, to, amount1);
    }

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external lock {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        _reserve0;
        _reserve1;
        data;
        if (amount0Out > 0) _safeTransfer(token0, to, amount0Out);
        if (amount1Out > 0) _safeTransfer(token1, to, amount1Out);
    }

    function _safeTransfer(address token, address to, uint value) private {
        (bool success,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, value));
        require(success, "transfer failed");
    }
}
