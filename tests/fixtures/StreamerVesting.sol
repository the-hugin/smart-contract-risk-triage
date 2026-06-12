interface IStreamToken {
    function balanceOf(address account) external view returns (uint256);
    function safeTransfer(address to, uint256 amount) external;
}

contract StreamerVesting {
    IStreamToken public immutable streamingAsset;
    address public immutable recipient;
    address public immutable returnAddress;
    uint256 public immutable nativeAssetStreamingAmount;
    uint256 public immutable claimCooldown;
    uint256 public immutable sweepCooldown;
    uint256 public immutable streamDuration;

    uint256 public startTimestamp;
    uint256 public lastClaimTimestamp;

    enum StreamState {
        NOT_INITIALIZED,
        STARTED,
        TERMINATED
    }

    StreamState public state;

    constructor(
        IStreamToken _streamingAsset,
        address _recipient,
        address _returnAddress,
        uint256 _nativeAssetStreamingAmount,
        uint256 _claimCooldown,
        uint256 _sweepCooldown,
        uint256 _streamDuration
    ) {
        streamingAsset = _streamingAsset;
        recipient = _recipient;
        returnAddress = _returnAddress;
        nativeAssetStreamingAmount = _nativeAssetStreamingAmount;
        claimCooldown = _claimCooldown;
        sweepCooldown = _sweepCooldown;
        streamDuration = _streamDuration;
    }

    function initialize() external {
        if (state != StreamState.NOT_INITIALIZED) revert();
        if (streamingAsset.balanceOf(address(this)) < nativeAssetStreamingAmount) revert();
        startTimestamp = block.timestamp;
        lastClaimTimestamp = block.timestamp;
        state = StreamState.STARTED;
    }

    function claim() external {
        if (block.timestamp < lastClaimTimestamp + claimCooldown) revert();
        lastClaimTimestamp = block.timestamp;
        streamingAsset.safeTransfer(recipient, nativeAssetStreamingAmount / streamDuration * claimCooldown);
    }

    function sweepRemaining() external {
        if (block.timestamp < startTimestamp + streamDuration + sweepCooldown) revert();
        state = StreamState.TERMINATED;
        streamingAsset.safeTransfer(returnAddress, streamingAsset.balanceOf(address(this)));
    }
}
