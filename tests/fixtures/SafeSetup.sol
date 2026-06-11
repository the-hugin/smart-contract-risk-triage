contract GnosisSafeProxy {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {
        _owners;
        _threshold;
        to;
        data;
        fallbackHandler;
        paymentToken;
        payment;
        paymentReceiver;
    }

    function checkNSignatures(bytes32 dataHash, bytes memory signatures) public view {
        dataHash;
        signatures;
    }
}
