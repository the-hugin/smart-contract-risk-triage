interface IAddressSubToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract AddressSubstitution {
    address public treasury;
    address public oracle;
    address public router;
    address public owner;
    IAddressSubToken public token;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setTreasury(address newTreasury) external {
        treasury = newTreasury;
    }

    function configureOracle(address newOracle) external {
        oracle = newOracle;
    }

    function withdrawTo(address recipient, uint256 amount) external {
        token.transfer(recipient, amount);
    }

    function drainNative(address payable to) external {
        to.transfer(address(this).balance);
    }

    function setRouter(address newRouter) external onlyOwner {
        router = newRouter;
    }
}
