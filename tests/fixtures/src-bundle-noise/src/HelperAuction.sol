contract Auction {
    address public governance;

    function initialize(address _governance) public {
        require(governance == address(0), "initialized");
        governance = _governance;
    }
}
