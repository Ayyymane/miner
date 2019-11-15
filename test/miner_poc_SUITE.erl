-module(miner_poc_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("blockchain/include/blockchain_vars.hrl").

-export([
    all/0
]).

-export([
    basic/1,
    poc_dist_v1_test/1,
    poc_dist_v2_test/1,
    poc_dist_v4_test/1,
    restart/1
]).

%%--------------------------------------------------------------------
%% COMMON TEST CALLBACK FUNCTIONS
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @public
%% @doc
%%   Running tests for this suite
%% @end
%%--------------------------------------------------------------------
all() ->
    [basic,
     poc_dist_v1_test,
     poc_dist_v2_test,
     poc_dist_v4_test,
     restart].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------
poc_dist_v1_test(Config0) ->
    TestCase = poc_dist_v1_test,
    Config = miner_ct_utils:init_per_testcase(TestCase, [{}, Config0]),
    N = proplists:get_value(num_consensus_members, Config),
    Interval = proplists:get_value(election_interval, Config),
    BatchSize = proplists:get_value(batch_size, Config),
    Curve = proplists:get_value(dkg_curve, Config),
    run_dist_with_params(TestCase,
                         Config,
                         #{?block_time => 5000, % BlockTime,
                           ?election_interval => Interval,
                           ?num_consensus_members => N,
                           ?batch_size => BatchSize,
                           ?dkg_curve => Curve,
                           ?poc_challenge_interval => 20}).

poc_dist_v2_test(Config0) ->
    TestCase = poc_dist_v2_test,
    Config = miner_ct_utils:init_per_testcase(TestCase, [{}, Config0]),
    N = proplists:get_value(num_consensus_members, Config),
    BlockTime = proplists:get_value(block_time, Config),
    Interval = proplists:get_value(election_interval, Config),
    BatchSize = proplists:get_value(batch_size, Config),
    Curve = proplists:get_value(dkg_curve, Config),
    run_dist_with_params(TestCase,
                         Config,
                         #{?block_time => BlockTime,
                           ?election_interval => Interval,
                           ?num_consensus_members => N,
                           ?batch_size => BatchSize,
                           ?dkg_curve => Curve,
                           ?poc_challenge_interval => 20,
                           ?poc_version => 2}).

poc_dist_v4_test(Config0) ->
    TestCase = poc_dist_v4_test,
    Config = miner_ct_utils:init_per_testcase(TestCase, [{}, Config0]),
    N = proplists:get_value(num_consensus_members, Config),
    BlockTime = proplists:get_value(block_time, Config),
    Interval = proplists:get_value(election_interval, Config),
    BatchSize = proplists:get_value(batch_size, Config),
    Curve = proplists:get_value(dkg_curve, Config),
    run_dist_with_params(TestCase,
                         Config,
                         #{?block_time => BlockTime,
                           ?election_interval => Interval,
                           ?num_consensus_members => N,
                           ?batch_size => BatchSize,
                           ?dkg_curve => Curve,
                           ?poc_challenge_interval => 20,
                           ?poc_version => 4,
                           ?poc_v4_target_challenge_age => 30}).

basic(_Config) ->
    BaseDir = "data/miner_poc_SUITE/basic",
    {PrivKey, PubKey} = miner_ct_utils:new_random_key(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    ECDHFun = libp2p_crypto:mk_ecdh_fun(PrivKey),
    Opts = [
        {key, {PubKey, SigFun, ECDHFun}},
        {seed_nodes, []},
        {port, 0},
        {num_consensus_members, 7},
        {base_dir, BaseDir}
    ],
    {ok, _Sup} = blockchain_sup:start_link(Opts),
    ?assert(erlang:is_pid(blockchain_swarm:swarm())),

    % Now add genesis
    % Generate fake blockchains (just the keys)
    RandomKeys = miner_ct_utils:generate_keys(6),
    Address = blockchain_swarm:pubkey_bin(),
    ConsensusMembers = [
        {Address, {PubKey, PrivKey, libp2p_crypto:mk_sig_fun(PrivKey)}}
    ] ++ RandomKeys,

    % Create genesis block
    Balance = 5000,
    ConbaseTxns = [blockchain_txn_coinbase_v1:new(Addr, Balance)
                     || {Addr, _} <- ConsensusMembers],
    ConbaseDCTxns = [blockchain_txn_dc_coinbase_v1:new(Addr, Balance)
                     || {Addr, _} <- ConsensusMembers],
    GenConsensusGroupTx = blockchain_txn_consensus_group_v1:new([Addr || {Addr, _} <- ConsensusMembers], <<>>, 1, 0),
    VarsKeys = libp2p_crypto:generate_keys(ecc_compact),
    VarsTx = miner_ct_utils:make_vars(VarsKeys, #{?poc_challenge_interval => 20}),

    Txs = ConbaseTxns ++ ConbaseDCTxns ++ [GenConsensusGroupTx] ++ VarsTx,
    GenesisBlock = blockchain_block_v1:new_genesis_block(Txs),
    ok = blockchain_worker:integrate_genesis_block(GenesisBlock),

    Chain = blockchain_worker:blockchain(),
    {ok, HeadBlock} = blockchain:head_block(Chain),

    ?assertEqual(blockchain_block:hash_block(GenesisBlock), blockchain_block:hash_block(HeadBlock)),
    ?assertEqual({ok, GenesisBlock}, blockchain:head_block(Chain)),
    ?assertEqual({ok, blockchain_block:hash_block(GenesisBlock)}, blockchain:genesis_hash(Chain)),
    ?assertEqual({ok, GenesisBlock}, blockchain:genesis_block(Chain)),
    ?assertEqual({ok, 1}, blockchain:height(Chain)),

    % All these point are in a line one after the other (except last)
    LatLongs = [
        {{37.780586, -122.469471}, {PrivKey, PubKey}},
        {{37.780959, -122.467496}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.78101, -122.465372}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781179, -122.463226}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781281, -122.461038}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781349, -122.458892}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781468, -122.456617}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781637, -122.4543}, miner_ct_utils:new_random_key(ecc_compact)}
    ],

    % Add a Gateway
    AddGatewayTxs = build_gateways(LatLongs, {PrivKey, PubKey}),
    ok = add_block(Chain, ConsensusMembers, AddGatewayTxs),

    ok = miner_ct_utils:wait_until(fun() -> {ok, 2} =:= blockchain:height(Chain) end),

    % Assert the Gateways location
    AssertLocaltionTxns = build_asserts(LatLongs, {PrivKey, PubKey}),
    ok = add_block(Chain, ConsensusMembers, AssertLocaltionTxns),

    ok = miner_ct_utils:wait_until(fun() -> {ok, 3} =:= blockchain:height(Chain) end),
    {ok, Statem} = miner_poc_statem:start_link(#{delay => 5}),

    ?assertEqual(requesting,  erlang:element(1, sys:get_state(Statem))),
    ?assertEqual(Chain, erlang:element(3, erlang:element(2, sys:get_state(Statem)))), % Blockchain is = to Chain
    ?assertEqual(requesting, erlang:element(6, erlang:element(2, sys:get_state(Statem)))), % State is requesting

    % Mock submit_txn to actually add the block
    meck:new(blockchain_worker, [passthrough]),
    meck:expect(blockchain_worker, submit_txn, fun(Txn) ->
        add_block(Chain, ConsensusMembers, [Txn])
    end),
    meck:new(miner_onion, [passthrough]),
    meck:expect(miner_onion, dial_framed_stream, fun(_, _, _) ->
        {ok, self()}
    end),

    meck:new(miner_onion_handler, [passthrough]),
    meck:expect(miner_onion_handler, send, fun(Stream, _Onion) ->
        ?assertEqual(self(), Stream)
    end),

    meck:new(blockchain_txn_poc_receipts_v1, [passthrough]),
    meck:expect(blockchain_txn_poc_receipts_v1, is_valid, fun(_, _) -> ok end),

    ?assertEqual(5, erlang:element(14, erlang:element(2, sys:get_state(Statem)))),

    % Add some block to start process
    ok = add_block(Chain, ConsensusMembers, []),

    % 3 previous blocks + 1 block to start process + 1 block with poc req txn
    ok = miner_ct_utils:wait_until(fun() -> {ok, 5} =:= blockchain:height(Chain) end),

    % Moving threw targeting and challenging
    ok = miner_ct_utils:wait_until(fun() ->
        case sys:get_state(Statem) of
            {receiving, _} -> true;
            _Other -> false
        end
    end),

    % Send 7 receipts and add blocks to pass timeout
    ?assertEqual(0, maps:size(erlang:element(11, erlang:element(2, sys:get_state(Statem))))),
    Challengees = erlang:element(9, erlang:element(2, sys:get_state(Statem))),
    ok = send_receipts(LatLongs, Challengees),
    timer:sleep(100),

    ?assertEqual(receiving, erlang:element(6, erlang:element(2, sys:get_state(Statem)))),
    ?assert(maps:size(erlang:element(11, erlang:element(2, sys:get_state(Statem)))) > 0), % Get reponses

    % Passing receiving_timeout
    lists:foreach(
        fun(_) ->
            ok = add_block(Chain, ConsensusMembers, []),
            timer:sleep(100)
        end,
        lists:seq(1, 10)
    ),

    ?assertEqual(receiving,  erlang:element(1, sys:get_state(Statem))),
    ?assertEqual(0, erlang:element(12, erlang:element(2, sys:get_state(Statem)))), % Get receiving_timeout
    ok = add_block(Chain, ConsensusMembers, []),

    ok = miner_ct_utils:wait_until(fun() ->
        case sys:get_state(Statem) of
            {waiting, _} -> true;
            {submitting, _} -> true;
            {requesting, _} -> true;
            {_Other, _} -> false
        end
    end),

    ?assert(meck:validate(blockchain_worker)),
    meck:unload(blockchain_worker),
    ?assert(meck:validate(miner_onion)),
    meck:unload(miner_onion),
    ?assert(meck:validate(miner_onion_handler)),
    meck:unload(miner_onion_handler),
    ?assert(meck:validate(blockchain_txn_poc_receipts_v1)),
    meck:unload(blockchain_txn_poc_receipts_v1),

    ok = gen_statem:stop(Statem),
    ok.

restart(_Config) ->
    BaseDir = "data/miner_poc_SUITE/restart",
    {PrivKey, PubKey} = miner_ct_utils:new_random_key(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    ECDHFun = libp2p_crypto:mk_ecdh_fun(PrivKey),
    Opts = [
        {key, {PubKey, SigFun, ECDHFun}},
        {seed_nodes, []},
        {port, 0},
        {num_consensus_members, 7},
        {base_dir, BaseDir}
    ],
    {ok, _Sup} = blockchain_sup:start_link(Opts),
    ?assert(erlang:is_pid(blockchain_swarm:swarm())),

    % Now add genesis
    % Generate fake blockchains (just the keys)
    RandomKeys = miner_ct_utils:generate_keys(6),
    Address = blockchain_swarm:pubkey_bin(),
    ConsensusMembers = [
        {Address, {PubKey, PrivKey, libp2p_crypto:mk_sig_fun(PrivKey)}}
    ] ++ RandomKeys,

    % Create genesis block
    Balance = 5000,
    ConbaseTxns = [blockchain_txn_coinbase_v1:new(Addr, Balance)
                     || {Addr, _} <- ConsensusMembers],
    ConbaseDCTxns = [blockchain_txn_dc_coinbase_v1:new(Addr, Balance)
                     || {Addr, _} <- ConsensusMembers],
    GenConsensusGroupTx = blockchain_txn_consensus_group_v1:new([Addr || {Addr, _} <- ConsensusMembers], <<>>, 1, 0),
    VarsKeys = libp2p_crypto:generate_keys(ecc_compact),
    VarsTx = miner_ct_utils:make_vars(VarsKeys, #{?poc_challenge_interval => 20}),

    Txs = ConbaseTxns ++ ConbaseDCTxns ++ [GenConsensusGroupTx] ++ VarsTx,
    GenesisBlock = blockchain_block_v1:new_genesis_block(Txs),
    ok = blockchain_worker:integrate_genesis_block(GenesisBlock),

    Chain = blockchain_worker:blockchain(),
    {ok, HeadBlock} = blockchain:head_block(Chain),

    ?assertEqual(blockchain_block:hash_block(GenesisBlock), blockchain_block:hash_block(HeadBlock)),
    ?assertEqual({ok, GenesisBlock}, blockchain:head_block(Chain)),
    ?assertEqual({ok, blockchain_block:hash_block(GenesisBlock)}, blockchain:genesis_hash(Chain)),
    ?assertEqual({ok, GenesisBlock}, blockchain:genesis_block(Chain)),
    ?assertEqual({ok, 1}, blockchain:height(Chain)),

    % All these point are in a line one after the other (except last)
    LatLongs = [
        {{37.780586, -122.469471}, {PrivKey, PubKey}},
        {{37.780959, -122.467496}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.78101, -122.465372}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781179, -122.463226}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781281, -122.461038}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781349, -122.458892}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781468, -122.456617}, miner_ct_utils:new_random_key(ecc_compact)},
        {{37.781637, -122.4543}, miner_ct_utils:new_random_key(ecc_compact)}
    ],

    % Add a Gateway
    AddGatewayTxs = build_gateways(LatLongs, {PrivKey, PubKey}),
    ok = add_block(Chain, ConsensusMembers, AddGatewayTxs),

    ok = miner_ct_utils:wait_until(fun() -> {ok, 2} =:= blockchain:height(Chain) end),

    % Assert the Gateways location
    AssertLocaltionTxns = build_asserts(LatLongs, {PrivKey, PubKey}),
    ok = add_block(Chain, ConsensusMembers, AssertLocaltionTxns),

    ok = miner_ct_utils:wait_until(fun() -> {ok, 3} =:= blockchain:height(Chain) end),

    {ok, Statem0} = miner_poc_statem:start_link(#{delay => 5,
                                                  base_dir => BaseDir}),

    ?assertEqual(requesting,  erlang:element(1, sys:get_state(Statem0))),
    ?assertEqual(Chain, erlang:element(3, erlang:element(2, sys:get_state(Statem0)))), % Blockchain is = to Chain
    ?assertEqual(requesting, erlang:element(6, erlang:element(2, sys:get_state(Statem0)))), % State is requesting

    % Mock submit_txn to actually add the block
    meck:new(blockchain_worker, [passthrough]),
    meck:expect(blockchain_worker, submit_txn, fun(Txn) ->
        add_block(Chain, ConsensusMembers, [Txn])
    end),
    meck:new(miner_onion, [passthrough]),
    meck:expect(miner_onion, dial_framed_stream, fun(_, _, _) ->
        {ok, self()}
    end),

    meck:new(miner_onion_handler, [passthrough]),
    meck:expect(miner_onion_handler, send, fun(Stream, _Onion) ->
        ?assertEqual(self(), Stream)
    end),

    meck:new(blockchain_txn_poc_receipts_v1, [passthrough]),
    meck:expect(blockchain_txn_poc_receipts_v1, is_valid, fun(_, _) -> ok end),

    ?assertEqual(5, erlang:element(14, erlang:element(2, sys:get_state(Statem0)))),

    % Add some block to start process
    ok = add_block(Chain, ConsensusMembers, []),

    % 3 previous blocks + 1 block to start process + 1 block with poc req txn
    ok = miner_ct_utils:wait_until(fun() -> {ok, 5} =:= blockchain:height(Chain) end),

    %% Moving through targeting and challenging
    ok = miner_ct_utils:wait_until(
           fun() ->
                   case sys:get_state(Statem0) of
                       {receiving, _} -> true;
                       _Other ->
                           ct:pal("other state ~p", [_Other]),
                           false
                   end
           end),

    % KILLING STATEM AND RESTARTING
    ok = gen_statem:stop(Statem0),
    {ok, Statem1} = miner_poc_statem:start_link(#{delay => 5,
                                                  base_dir => BaseDir}),

    ?assertEqual(receiving,  erlang:element(1, sys:get_state(Statem1))),
    ?assertEqual(receiving, erlang:element(6, erlang:element(2, sys:get_state(Statem1)))),

    % Send 7 receipts and add blocks to pass timeout
    ?assertEqual(0, maps:size(erlang:element(11, erlang:element(2, sys:get_state(Statem1))))),
    Challengees = erlang:element(9, erlang:element(2, sys:get_state(Statem1))),
    ok = send_receipts(LatLongs, Challengees),
    timer:sleep(100),

    ?assertEqual(receiving,  erlang:element(1, sys:get_state(Statem1))),
    ?assertEqual(receiving, erlang:element(6, erlang:element(2, sys:get_state(Statem1)))),
    ?assert(maps:size(erlang:element(11, erlang:element(2, sys:get_state(Statem1)))) > 0), % Get reponses

    % Passing receiving_timeout
    lists:foreach(
        fun(_) ->
            ok = add_block(Chain, ConsensusMembers, []),
            timer:sleep(100)
        end,
        lists:seq(1, 10)
    ),

    ?assertEqual(receiving,  erlang:element(1, sys:get_state(Statem1))),
    ?assertEqual(0, erlang:element(12, erlang:element(2, sys:get_state(Statem1)))), % Get receiving_timeout
    ok = add_block(Chain, ConsensusMembers, []),

    ok = miner_ct_utils:wait_until(
           fun() ->
                   case sys:get_state(Statem1) of
                       {waiting, _} -> true;
                       {submitting, _} -> true;
                       {requesting, _} -> true;
                       {_Other, _} ->
                           ct:pal("other state ~p", [_Other]),
                           false
                   end
           end),

    ?assert(meck:validate(blockchain_worker)),
    meck:unload(blockchain_worker),
    ?assert(meck:validate(miner_onion)),
    meck:unload(miner_onion),
    ?assert(meck:validate(miner_onion_handler)),
    meck:unload(miner_onion_handler),
    ?assert(meck:validate(blockchain_txn_poc_receipts_v1)),
    meck:unload(blockchain_txn_poc_receipts_v1),

    ok = gen_statem:stop(Statem1),
    ok.


%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

add_block(Chain, ConsensusMembers, Txns) ->
    SortedTxns = lists:sort(fun blockchain_txn:sort/2, Txns),
    B = create_block(ConsensusMembers, SortedTxns),
    ok = blockchain:add_block(B, Chain).

send_receipts(LatLongs, Challengees) ->
    lists:foreach(
        fun({_LatLong, {PrivKey, PubKey}}) ->
            Address = libp2p_crypto:pubkey_to_bin(PubKey),
            SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
            {Mega, Sec, Micro} = os:timestamp(),
            Timestamp = Mega * 1000000 * 1000000 + Sec * 1000000 + Micro,
            case lists:keyfind(Address, 1, Challengees) of
                {Address, LayerData} ->
                    Receipt = blockchain_poc_receipt_v1:new(Address, Timestamp, 0, LayerData, radio),
                    SignedReceipt = blockchain_poc_receipt_v1:sign(Receipt, SigFun),
                    miner_poc_statem:receipt(SignedReceipt);
                _ ->
                    ok
            end
        end,
        LatLongs
    ).

build_asserts(LatLongs, {PrivKey, PubKey}) ->
    lists:foldl(
        fun({LatLong, {GatewayPrivKey, GatewayPubKey}}, Acc) ->
            Gateway = libp2p_crypto:pubkey_to_bin(GatewayPubKey),
            GatewaySigFun = libp2p_crypto:mk_sig_fun(GatewayPrivKey),
            OwnerSigFun = libp2p_crypto:mk_sig_fun(PrivKey),
            Owner = libp2p_crypto:pubkey_to_bin(PubKey),
            Index = h3:from_geo(LatLong, 12),
            AssertLocationRequestTx = blockchain_txn_assert_location_v1:new(Gateway, Owner, Index, 1, 1, 0),
            PartialAssertLocationTxn = blockchain_txn_assert_location_v1:sign_request(AssertLocationRequestTx, GatewaySigFun),
            SignedAssertLocationTx = blockchain_txn_assert_location_v1:sign(PartialAssertLocationTxn, OwnerSigFun),
            [SignedAssertLocationTx|Acc]
        end,
        [],
        LatLongs
    ).

build_gateways(LatLongs, {PrivKey, PubKey}) ->
    lists:foldl(
        fun({_LatLong, {GatewayPrivKey, GatewayPubKey}}, Acc) ->
            % Create a Gateway
            Gateway = libp2p_crypto:pubkey_to_bin(GatewayPubKey),
            GatewaySigFun = libp2p_crypto:mk_sig_fun(GatewayPrivKey),
            OwnerSigFun = libp2p_crypto:mk_sig_fun(PrivKey),
            Owner = libp2p_crypto:pubkey_to_bin(PubKey),

            AddGatewayTx = blockchain_txn_add_gateway_v1:new(Owner, Gateway, 1, 0),
            SignedOwnerAddGatewayTx = blockchain_txn_add_gateway_v1:sign(AddGatewayTx, OwnerSigFun),
            SignedGatewayAddGatewayTx = blockchain_txn_add_gateway_v1:sign_request(SignedOwnerAddGatewayTx, GatewaySigFun),
            [SignedGatewayAddGatewayTx|Acc]

        end,
        [],
        LatLongs
    ).

create_block(ConsensusMembers, Txs) ->
    Blockchain = blockchain_worker:blockchain(),
    {ok, PrevHash} = blockchain:head_hash(Blockchain),
    {ok, HeadBlock} = blockchain:head_block(Blockchain),
    Height = blockchain_block:height(HeadBlock) + 1,
    Block0 = blockchain_block_v1:new(#{prev_hash => PrevHash,
                                       height => Height,
                                       transactions => Txs,
                                       signatures => [],
                                       time => 0,
                                       hbbft_round => 0,
                                       election_epoch => 1,
                                       epoch_start => 1}),
    BinBlock = blockchain_block:serialize(blockchain_block:set_signatures(Block0, [])),
    Signatures = signatures(ConsensusMembers, BinBlock),
    Block1 = blockchain_block:set_signatures(Block0, Signatures),
    Block1.

signatures(ConsensusMembers, BinBlock) ->
    lists:foldl(
        fun({A, {_, _, F}}, Acc) ->
            Sig = F(BinBlock),
            [{A, Sig}|Acc]
        end
        ,[]
        ,ConsensusMembers
    ).

new_random_key(Curve) ->
    #{secret := PrivKey, public := PubKey} = libp2p_crypto:generate_keys(Curve),
    {PrivKey, PubKey}.

run_dist_with_params(TestCase, Config, VarMap) ->
    ok = setup_dist_test(Config, VarMap),
    miner_ct_utils:end_per_testcase(TestCase, Config),
    ok.

setup_dist_test(Config, VarMap) ->
    Miners = proplists:get_value(miners, Config),
    miner_fake_radio_backplane:start_link(45000, lists:seq(46001, 46008)),
    ok = initialize_chain(Miners, Config, VarMap),
    GenesisBlock = get_genesis_block(Miners, Config),
    timer:sleep(5000),
    ok = load_genesis_block(GenesisBlock, Miners, Config),
    %% wait till height 50
    ok = wait_until_height(Miners, 50),
    %% check that every miner has issued a challenge
    ?assert(check_all_miners_can_challenge(Miners, find_requests(Miners))),

    ReceiptMap = find_receipts(Miners),
    ct:pal("ReceiptMap: ~p", [ReceiptMap]),

    ok.

initialize_chain(Miners, Config, VarMap) ->
    Addresses = proplists:get_value(addresses, Config),
    N = proplists:get_value(num_consensus_members, Config),
    Curve = proplists:get_value(dkg_curve, Config),
    Keys = libp2p_crypto:generate_keys(ecc_compact),
    InitialVars = miner_ct_utils:make_vars(Keys, VarMap),
    InitialPaymentTransactions = [blockchain_txn_coinbase_v1:new(Addr, 5000) || Addr <- Addresses],
    Locations = lists:foldl(
        fun(I, Acc) ->
            [h3:from_geo({37.780586, -122.469470 + I/100}, 13)|Acc]
        end,
        [],
        lists:seq(1, length(Addresses))
    ),
    IntitialGatewayTransactions = [blockchain_txn_gen_gateway_v1:new(Addr, Addr, Loc, 0) || {Addr, Loc} <- lists:zip(Addresses, Locations)],
    InitialTransactions = InitialVars ++ InitialPaymentTransactions ++ IntitialGatewayTransactions,
    DKGResults = miner_ct_utils:pmap(
        fun(Miner) ->
            ct_rpc:call(Miner, miner_consensus_mgr, initial_dkg, [InitialTransactions, Addresses, N, Curve])
        end,
        Miners
    ),
    ct:pal("results ~p", [DKGResults]),
    ?assert(lists:all(fun(Res) -> Res == ok end, DKGResults)),
    ok.

get_genesis_block(Miners, Config) ->
    RPCTimeout = proplists:get_value(rpc_timeout, Config),
    ct:pal("RPCTimeout: ~p", [RPCTimeout]),
    %% obtain the genesis block
    GenesisBlock = lists:foldl(
                     fun(Miner, undefined) ->
                             case ct_rpc:call(Miner, blockchain_worker, blockchain, [], RPCTimeout) of
                                 {badrpc, Reason} ->
                                     ct:fail(Reason),
                                     false;
                                 undefined ->
                                     false;
                                 Chain ->
                                     {ok, GBlock} = rpc:call(Miner, blockchain, genesis_block, [Chain]),
                                     GBlock
                             end;
                        (_, Acc) ->
                             Acc
                     end,
                     undefined,
                     Miners
                    ),

    ?assertNotEqual(undefined, GenesisBlock),
    GenesisBlock.

load_genesis_block(GenesisBlock, Miners, Config) ->
    RPCTimeout = proplists:get_value(rpc_timeout, Config),
    %% load the genesis block on all the nodes
    lists:foreach(
        fun(Miner) ->
                case ct_rpc:call(Miner, miner_consensus_mgr, in_consensus, [], 5000) of
                    true ->
                        ok;
                    false ->
                        ct_rpc:call(Miner, blockchain_worker,
                                    integrate_genesis_block, [GenesisBlock], 5000)
                end
        end,
        Miners
    ),

    timer:sleep(5000),

    %% Check chain on each miner
    lists:foreach(
        fun(Miner) ->
                Chain = ct_rpc:call(Miner, blockchain_worker, blockchain, [], RPCTimeout),
                ?assertNotEqual(Chain, undefined),
                {ok, Height} = ct_rpc:call(Miner, blockchain, height, [Chain], RPCTimeout),
                ct:pal("Miner: ~p,\nChain: ~p,\nHeight: ~p", [Miner, Chain, Height])
        end,
        Miners
    ),
    ok.

wait_until_height(Miners, Height) ->
    miner_ct_utils:wait_until(
      fun() ->
              Heights = lists:map(fun(Miner) ->
                                          C = ct_rpc:call(Miner, blockchain_worker, blockchain, []),
                                          {ok, H} = ct_rpc:call(Miner, blockchain, height, [C]),
                                          H
                                  end,
                                  Miners),
              ct:pal("Heights: ~w", [Heights]),

              true == lists:all(fun(H) ->
                                        H >= Height
                                end,
                                Heights)
      end,
      60,
      timer:seconds(5)).

find_requests(Miners) ->
    [M | _] = Miners,
    Chain = ct_rpc:call(M, blockchain_worker, blockchain, []),
    Blocks = ct_rpc:call(M, blockchain, blocks, [Chain]),
    lists:flatten(lists:foldl(fun({_Hash, Block}, Acc) ->
                                      Txns = blockchain_block:transactions(Block),
                                      Requests = lists:filter(fun(T) ->
                                                                      blockchain_txn:type(T) == blockchain_txn_poc_request_v1
                                                              end,
                                                              Txns),
                                      [Requests | Acc]
                              end,
                              [],
                              maps:to_list(Blocks))).

find_receipts(Miners) ->
    [M | _] = Miners,
    Chain = ct_rpc:call(M, blockchain_worker, blockchain, []),
    Blocks = ct_rpc:call(M, blockchain, blocks, [Chain]),
    lists:foldl(fun({_Hash, Block}, Acc) ->
                        Txns = blockchain_block:transactions(Block),
                        Height = blockchain_block:height(Block),
                        Receipts = lists:filter(fun(T) ->
                                                        blockchain_txn:type(T) == blockchain_txn_poc_receipts_v1
                                                end,
                                                Txns),
                        lists:map(fun(Receipt) ->
                                          Challenger = blockchain_txn_poc_receipts_v1:challenger(Receipt),
                                          NewVal = maps:get(Challenger, Acc, []),
                                          maps:put(Challenger, [{Height, Receipt} | NewVal], Acc)
                                  end,
                                  Receipts)
                end,
                #{},
                maps:to_list(Blocks)).

check_all_miners_can_challenge(Miners, TotalRequests) ->
    MinerNames = sets:from_list(lists:map(fun(Miner) ->
                                                  PubkeyBin = ct_rpc:call(Miner, blockchain_swarm, pubkey_bin, []),
                                                  {ok, Name} = erl_angry_purple_tiger:animal_name(libp2p_crypto:bin_to_b58(PubkeyBin)),
                                                  Name
                                          end,
                                          Miners)),

    UniqChallengers = sets:from_list(lists:map(fun(R) ->
                                                       {ok, Challenger} = erl_angry_purple_tiger:animal_name(libp2p_crypto:bin_to_b58(blockchain_txn_poc_request_v1:challenger(R))),
                                                       Challenger
                                               end,
                                               TotalRequests)),

    ct:pal("MinerNames: ~p", [sets:to_list(MinerNames)]),
    ct:pal("UniqChallengers: ~p", [sets:to_list(UniqChallengers)]),

    case MinerNames == UniqChallengers of
        false ->
            ct:pal("Not every miner has issued a challenge...waiting..."),
            %% wait 40 more blocks?
            NewHeight = get_current_height(Miners),
            NewTotalRequests = find_requests(Miners),
            wait_until_height(Miners, NewHeight + 40),
            check_all_miners_can_challenge(Miners, NewTotalRequests);
        true ->
            ct:pal("Got a challenge from each miner atleast once!"),
            true
    end.

get_current_height(Miners) ->
    [M | _] = Miners,
    Chain = ct_rpc:call(M, blockchain_worker, blockchain, []),
    {ok, Height} = ct_rpc:call(M, blockchain, height, [Chain]),
    Height.
