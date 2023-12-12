// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "@cartesi/rollups/contracts/inputs/IInputBox.sol";
import "@chainlink/contracts/src/v0.8/vrf/VRFV2WrapperConsumerBase.sol";

contract CoinToss is VRFV2WrapperConsumerBase {
    address deployer;
    address public L2_DAPP;
    Game public last_game;
    IInputBox inputBox = IInputBox(0x59b22D57D4f067708AB0c00552767405926dc768);

    struct Game {
        address winner;
        address pending_player;
        bool exists;
    }

    struct Games {
        uint256 current_match_id; // initial value is 0
        mapping (uint => Game) matches;
    }

    mapping (bytes => Games) games; // maps gamekey to gameID

    ////////////////////////////////////
    // CHAINLINK variables and functions
    ////////////////////////////////////
    mapping(uint256 => bytes) public randomness_requests; /* requestId --> gamekey */

    // Depends on the number of requested values that you want sent to the
    // requestRandomness() function. Test and adjust
    // this limit based on the network that you select, the size of the request,
    // and the processing of the callback request in the fulfillRandomWords()
    // function.
    uint32 callbackGasLimit = 500000;

    // The default is 3, but you can set this higher.
    uint16 requestConfirmations = 3;

    // For this example, retrieve 1 random values in one request.
    // Cannot exceed VRFV2Wrapper.getConfig().maxNumWords.
    uint32 numWords = 1;

    // Address LINK - hardcoded for Sepolia
    address constant linkAddress = 0x779877A7B0D9E8603169DdbD7836e478b4624789;

    // address WRAPPER - hardcoded for Sepolia
    address constant wrapperAddress = 0xab18414CD93297B0d12ac29E63Ca20f515b3DB46;

    function l2_coin_toss(bytes memory gamekey) private returns (uint256 requestId) {
        requestId = requestRandomness(
            callbackGasLimit,
            requestConfirmations,
            numWords
        );

        randomness_requests[requestId] = gamekey;
        return requestId;
    }

    function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords) internal override {
        bytes memory gamekey = randomness_requests[_requestId];

        uint256 coin_toss_seed = _randomWords[0];
        bytes memory payload = abi.encode(gamekey, coin_toss_seed);

        // calls Cartesi's addInput to run the "coin toss" inside Cartesi Machine
        inputBox.addInput(L2_DAPP, payload);
    }

    constructor() VRFV2WrapperConsumerBase(linkAddress, wrapperAddress) {
        deployer = msg.sender;
    }

    function set_dapp_address(address l2_dapp) public {
        require(msg.sender == deployer);

        L2_DAPP = l2_dapp;
    }

    function get_gamekey(address player, address opponent) internal pure returns (bytes memory) {
        bytes memory gamekey;
        if (player < opponent) {
            gamekey = abi.encode(player, opponent);
        } else {
            gamekey = abi.encode(opponent, player);
        }

        return gamekey;
    }

    // used to create or play game between two players
    function play(address opponent) public {
        require(L2_DAPP != address(0));

        bytes memory gamekey = get_gamekey(msg.sender, opponent);
        Game storage game = games[gamekey].matches[games[gamekey].current_match_id];

        require(!game.exists || game.pending_player == msg.sender);

        if (!game.exists) {
            game.pending_player = opponent;
            game.exists = true;
        } else if (game.pending_player == msg.sender) {
            l2_coin_toss(gamekey);
            game.pending_player = address(0);
        }
    }

    function announce_winner(address player1, address player2, address winner) public {
        require(msg.sender == L2_DAPP && (winner == player1 || winner == player2));

        bytes memory gamekey = get_gamekey(player1, player2);
        Game storage game = games[gamekey].matches[games[gamekey].current_match_id];

        require(game.exists);

        emit GameResult(gamekey, games[gamekey].current_match_id, winner);

        game.winner = winner;
        games[gamekey].current_match_id++;

        last_game = game;
    }

    event GameResult (
        bytes gamekey,
        uint256 gameId,
        address winner
    );
}