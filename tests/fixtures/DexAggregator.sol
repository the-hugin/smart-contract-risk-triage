contract DexAggregator {
    modifier onlyFundManager() {
        _;
    }

    struct TransferParam {
        Token assetAddress;
        address recipient;
        uint256 amount;
    }

    function transferMany(TransferParam[] calldata transferParams) external onlyFundManager {
        for (uint256 i = 0; i < transferParams.length; ) {
            transferParams[i].assetAddress.transfer(transferParams[i].recipient, transferParams[i].amount);
            unchecked {
                i++;
            }
        }
    }
}

interface Token {
    function transfer(address to, uint256 amount) external returns (bool);
}
