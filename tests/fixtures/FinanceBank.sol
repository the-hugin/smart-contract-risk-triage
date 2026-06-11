contract finance_Bank {
    function Deposit(uint _unlockTime) public payable {
        Holder storage acc = Accounts[msg.sender];
        acc.balance += msg.value;
        acc.unlockTime = _unlockTime > block.timestamp ? _unlockTime : block.timestamp;
    }

    function Collect(uint _am) public payable {
        Holder storage acc = Accounts[msg.sender];
        if (acc.balance > MinSum && acc.balance >= _am && block.timestamp > acc.unlockTime) {
            (bool success, ) = msg.sender.call{value: _am}("");
            if (success) {
                acc.balance -= _am;
            }
        }
    }

    struct Holder {
        uint unlockTime;
        uint balance;
    }

    mapping(address => Holder) public Accounts;
    uint public MinSum = 1 ether;
}
