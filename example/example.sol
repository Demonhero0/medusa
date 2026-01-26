/*
 * @article: https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620
 * @source: https://etherscan.io/address/0xa11e4ed59dc94e69612f3111942626ed513cb172#code
 * @vulnerable_at_lines: 43
 * @author: -
 */

 pragma solidity ^0.4.15;

/// @title Ethereum Lottery Game.

contract Example {

    // Amount of ether needed for participating in the lottery.
    uint constant TICKET_AMOUNT = 10;

    // Fixed amount fee for each lottery game.
    uint constant FEE_AMOUNT = 1;

    // Address where fee is sent.
    address public bank;

    // Public jackpot that each participant can win (minus fee).
    uint public pot;

    // Lottery constructor sets bank account from the smart-contract owner.
    function EtherLotto() payable {
        bank = msg.sender;
    }

    // Public function for playing lottery. Each time this function
    // is invoked, the sender has an oportunity for winning pot.
    function play() payable {

        // Participants must spend some fixed ether before playing lottery.
        // assert(msg.value == TICKET_AMOUNT);

        // Increase pot for each participant.
        pot += msg.value;

        // Compute some *almost random* value for selecting winner from current transaction.
        var r = block.timestamp + 1;

        // <yes> <report> TIME_MANIPULATION
        var random = uint(sha3(block.timestamp)) % 2;

        // Distribution: 50% of participants will be winners.
        if (random == 0) {

            // Send fee to bank account.
            bank.transfer(FEE_AMOUNT);

            // Send jackpot to winner.
            msg.sender.transfer(pot - FEE_AMOUNT);

            // Restart jackpot.
            pot = 0;
        }
    }

    mapping (address => uint) userBalances;

    function getBalance(address user) constant returns(uint) {  
		return userBalances[user];
	}

	function addToBalance() payable {
		userBalances[msg.sender] += msg.value;
	}

	function withdrawBalance() {  
		uint amountToWithdraw = userBalances[msg.sender];
        // <yes> <report> REENTRANCY
		if (!(msg.sender.call.value(amountToWithdraw)())) { throw; }
		userBalances[msg.sender] = 0;
	}    

      address callee;
        address owner;

        modifier onlyOwner {
            require(msg.sender == owner);
            _;
        }

        constructor() public payable {
            callee = address(0x0);
            owner = msg.sender;
        }

        function setCallee(address newCallee) public onlyOwner {
            callee = newCallee;
        }

        function forward(bytes _data) public {
            require(callee.delegatecall(_data));
        }

      // <yes> <report> ACCESS_CONTROL
  function sudicideAnyone() {
    selfdestruct(msg.sender); // <SUICIDAL_VUL>, <LEAKING_VUL>
  }



    uint public count = 1;
    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        count += input;
    }
}