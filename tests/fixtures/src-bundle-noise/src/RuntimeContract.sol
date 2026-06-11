contract RuntimeContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }
}
