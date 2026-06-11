interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function burnFrom(address account, uint256 amount) external;
}

contract CommentExample {
    /*
    function doThing(address token, uint256 value) public {
        token.safeTransferFrom(msg.sender, address(this), value);
    }
    */
    function realView() external pure returns (uint256) {
        return 1;
    }
}

contract GnosisSafe {
    function checkSignatures(bytes32, bytes memory, bytes memory) public view {}

    function handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private returns (uint256 payment) {
        address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
        payment = gasUsed + baseGas + gasPrice;
        if (gasToken == address(0)) {
            require(receiver.send(payment), "GS011");
        }
    }
}

contract FactoryWallet {
    address public immutable factory;
    address public owner;
    bool private initialized;
    IERC20Like public usdc;

    constructor() {
        factory = msg.sender;
    }

    modifier onlyFactory() {
        require(msg.sender == factory, "caller is not factory");
        _;
    }

    function init(address _owner, address _usdc) external onlyFactory {
        require(!initialized, "already initialized");
        owner = _owner;
        usdc = IERC20Like(_usdc);
        initialized = true;
    }
}

contract FixedRecipientForwarder {
    address payable public ownerAddress;
    address public yodlFeeTreasury;

    function flush() public {
        (bool success,) = ownerAddress.call{value: address(this).balance}("");
        require(success, "flush failed");
    }

    function sweep(address token) external {
        IERC20Like(token).transfer(yodlFeeTreasury, IERC20Like(token).balanceOf(address(this)));
    }
}

contract EntryPointAndPortalGated {
    address public entryPoint;
    Outbox public outbox;
    IERC20Like public token;

    function _requireFromEntryPoint() internal view {
        require(msg.sender == entryPoint, "not entrypoint");
    }

    function validatePaymasterUserOp(address user, uint256 amount) external {
        _requireFromEntryPoint();
        token.transferFrom(user, address(this), amount);
    }

    function withdraw(address recipient, uint256 amount, bytes calldata message) external {
        outbox.consume(message);
        token.transfer(recipient, amount);
    }
}

contract CostBoundPayout {
    IERC20Like public token;
    IERC20Like public receipt;
    uint256 public accumulatedProtocolFees;

    function redeemFeeVault() external returns (uint256 amount) {
        amount = accumulatedProtocolFees;
        accumulatedProtocolFees = 0;
        receipt.burnFrom(msg.sender, 100 ether);
        token.safeTransfer(msg.sender, amount);
    }
}

contract InboundDeposit {
    IERC20Like public token;

    function depositToken(address fromAddress, uint256 amount) external {
        token.transferFrom(fromAddress, address(this), amount);
    }
}

interface Outbox {
    function consume(bytes calldata message) external;
}
