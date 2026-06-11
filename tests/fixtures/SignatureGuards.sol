contract SignatureGuards {
    mapping(bytes32 => bool) public filledQuotes;
    mapping(bytes32 => bool) public usedCodes;
    mapping(address => uint256) public mintCount;
    address public trustedSigner;
    address public signerAddress;
    uint256 public nonce;

    function fillQuote(
        bytes32 quoteHash,
        address caller,
        uint256 chainId,
        address verifyingContract,
        uint256 expiration,
        bytes calldata signature
    ) external {
        require(msg.sender == caller, "bad caller");
        require(chainId == block.chainid, "bad chain");
        require(verifyingContract == address(this), "bad contract");
        require(block.timestamp <= expiration, "expired");
        require(!filledQuotes[quoteHash], "filled");
        address recovered = ECDSA.recover(quoteHash, signature);
        require(recovered == trustedSigner, "bad signer");
        filledQuotes[quoteHash] = true;
    }

    function mint(string calldata rawCode, bytes calldata signature) external payable {
        require(msg.value == 1 ether, "wrong eth");
        require(mintCount[msg.sender] < 1, "limit");
        bytes32 codeHash = keccak256(abi.encodePacked(rawCode));
        require(!usedCodes[codeHash], "used");
        address recovered = ECDSA.recover(codeHash, signature);
        require(recovered == signerAddress, "invalid");
        usedCodes[codeHash] = true;
        mintCount[msg.sender]++;
        nonce++;
    }
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        signature;
        return address(uint160(uint256(hash)));
    }
}
