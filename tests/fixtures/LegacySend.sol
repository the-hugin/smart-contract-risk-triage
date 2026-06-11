contract LegacySend {
    struct Investor {
        uint256 balance;
    }

    mapping(address => Investor) public investors;

    function payout() external {
        Investor storage investor = investors[msg.sender];
        if (investor.balance == 0) {
            throw;
        }
        msg.sender.send(investor.balance);
        investor.balance = 0;
    }
}
