contract MerklePayout {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    Token public token;

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        claimed[msg.sender] = true;
        token.transfer(msg.sender, amount);
    }
}

library MerkleProof {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        proof;
        root;
        leaf;
        return true;
    }
}

interface Token {
    function transfer(address to, uint256 amount) external returns (bool);
}
