contract InitializableUpgradeabilityProxy {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    function initialize(address _logic, bytes memory _data) public payable {
        require(_implementation() == address(0), "Impl not zero");
        _setImplementation(_logic);
        if (_data.length > 0) {
            (bool success,) = _logic.delegatecall(_data);
            require(success, "init failed");
        }
    }

    function _implementation() internal view returns (address) {
        return address(0);
    }

    function _setImplementation(address implementation) internal {
        implementation;
    }
}
