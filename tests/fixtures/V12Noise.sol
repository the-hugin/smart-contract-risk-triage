interface ITokenV12 {
    function transfer(address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract SimpleStorageV12 {
    uint256 public value;

    function set(uint256 newValue) external {
        value = newValue;
    }
}

contract PausableViewV12 {
    bool private halted;

    function paused() external view returns (bool) {
        return halted;
    }
}

contract PublicConfigV12 {
    bool public swapEnabled;
    uint256 public swapThreshold;
    uint256 public targetLiquidity;

    function setSwapBackSettings(bool enabled, uint256 threshold) external {
        swapEnabled = enabled;
        swapThreshold = threshold;
    }

    function setTargetLiquidity(uint256 value) external {
        targetLiquidity = value;
    }
}

contract KeeperBountyV12 {
    address payable public treasury;
    uint256 public lastRun;
    uint256 public cooldown = 1 hours;
    uint256 public bountyCap = 0.01 ether;

    function skimExcess(uint256 bounty) external {
        require(block.timestamp > lastRun + cooldown, "cooldown");
        require(bounty <= bountyCap, "cap");
        lastRun = block.timestamp;
        payable(msg.sender).transfer(bounty);
        treasury.transfer(address(this).balance);
    }
}

contract UserFundedRedemptionV12 {
    ITokenV12 public token;
    ITokenV12 public receipt;

    function redeem(uint256 amount) external {
        receipt.safeTransferFrom(msg.sender, address(this), amount);
        token.safeTransfer(msg.sender, amount);
    }
}

contract SelfScopedOperatorV12 {
    mapping(address => mapping(address => bool)) private _blorbOperators;

    function setBlorbOperator(address op, bool ok) external {
        _blorbOperators[msg.sender][op] = ok;
    }
}

contract GameRoundV12 {
    mapping(address => uint256) public pendingETH;

    function claimJackpot() external {
        uint256 amount = pendingETH[msg.sender];
        pendingETH[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

contract FixedRecipientV12 {
    ITokenV12 public token;
    address public marketingFeeReceiver;

    function collectFees() external {
        token.transfer(marketingFeeReceiver, token.balanceOf(address(this)));
    }
}

contract StandardApprovalV12 {
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    function setApprovalForAll(address operator, bool approved) public {
        _operatorApprovals[msg.sender][operator] = approved;
    }
}

contract TimelockedConfigV12 {
    address public curator;
    mapping(bytes => uint256) public executableAt;
    uint256 public performanceFee;

    function submit(bytes calldata data) external {
        require(msg.sender == curator, "curator");
        executableAt[data] = block.timestamp + 1 days;
    }

    function timelocked() internal {
        require(executableAt[msg.data] != 0, "not queued");
        require(block.timestamp >= executableAt[msg.data], "too early");
        executableAt[msg.data] = 0;
    }

    function setPerformanceFee(uint256 newFee) external {
        timelocked();
        performanceFee = newFee;
    }
}

contract IfAdminProxyV12 {
    address public admin;

    modifier ifAdmin() {
        require(msg.sender == admin, "admin");
        _;
    }

    function upgradeTo(address newImplementation) external ifAdmin {
        newImplementation;
    }
}

contract EoaGateEventV12 {
    event Buy(address indexed account, uint256 amount);

    function buy(uint256 amount) external {
        require(tx.origin == msg.sender, "no contracts");
        emit Buy(tx.origin, amount);
    }
}

interface IPoolManagerV14 {
    function take(address currency, address to, uint256 amount) external;
}

interface IUpgradeSourceV14 {
    function shouldUpgrade() external view returns (bool, address);
}

contract HookAttributionV14 {
    IPoolManagerV14 public poolManager;
    mapping(address => uint256) public lastBuyBlock;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "pool manager");
        _;
    }

    function beforeSwap(address currency, uint256 fee) external onlyPoolManager {
        address trader = tx.origin;
        lastBuyBlock[trader] = block.number;
        if (fee > 0) {
            poolManager.take(currency, address(this), fee);
        }
    }
}

contract DebtBackedLiquidationV14 {
    ITokenV12 public token;

    struct Position {
        uint256 debt;
        uint256 collateral;
    }

    mapping(address => Position) public positions;
    uint256 public totalDebt;

    function liquidate(address victim) external payable {
        Position storage p = positions[victim];
        if (p.debt == 0) revert();
        if (msg.value < p.debt) revert();
        if (p.collateral * 10_000 >= p.debt * 15_000) revert();
        uint256 reward = p.debt / 100;
        totalDebt -= p.debt;
        delete positions[victim];
        token.transfer(msg.sender, reward);
    }
}

contract SecretGatedV14 {
    bytes32 private immutable seal;

    constructor(bytes32 _seal) payable {
        seal = _seal;
    }

    function pierce(bytes32 key, address payable to) external {
        if (keccak256(abi.encode(key, to)) != seal) revert();
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "transfer");
    }
}

contract ScheduledUpgradeV14 {
    function upgrade() external {
        (bool should, address nextImplementation) = IUpgradeSourceV14(address(this)).shouldUpgrade();
        require(should, "scheduled");
        _upgradeTo(nextImplementation);
        (bool success,) = address(this).delegatecall(abi.encodeWithSignature("finalizeUpgrade()"));
        require(success, "finalize");
    }

    function _upgradeTo(address nextImplementation) internal {
        nextImplementation;
    }
}

contract PostExpiryMaintenanceV14 {
    bool public expired;
    uint256 public cachedIndex;

    function isExpired() public view returns (bool) {
        return expired;
    }

    function setPostExpiryData() external {
        if (isExpired()) {
            cachedIndex = block.timestamp;
        }
    }
}

contract SelfScopedMarketInitV14 {
    struct Curve {
        uint64 target;
    }

    mapping(address => Curve) public accountantToCurve;

    function initializeYDMForMarket(uint64 target) external {
        accountantToCurve[msg.sender].target = target;
    }
}
