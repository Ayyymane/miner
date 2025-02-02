-module(miner_dkg_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/inet.hrl").

-export([
         init_per_suite/1
         ,end_per_suite/1
         ,init_per_testcase/2
         ,end_per_testcase/2
         ,all/0
        ]).

-export([
         initial_dkg_test/1
        ]).

%% common test callbacks

all() -> [
          initial_dkg_test
         ].

init_per_suite(Config) ->
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(_TestCase, Config) ->
    miner_ct_utils:init_per_testcase(_TestCase, Config).

end_per_testcase(_TestCase, Config) ->
    miner_ct_utils:end_per_testcase(_TestCase, Config).

initial_dkg_test(Config) ->
    Miners = proplists:get_value(miners, Config),
    Addresses = proplists:get_value(addresses, Config),
    Keys = libp2p_crypto:generate_keys(ecc_compact),

    InitialVars = miner_ct_utils:make_vars(Keys, #{}),
    InitialPaymentTransactions = [blockchain_txn_coinbase_v1:new(Addr, 5000) || Addr <- Addresses],
    InitialTransactions = InitialVars ++ InitialPaymentTransactions,
    N = proplists:get_value(num_consensus_members, Config),
    Curve = proplists:get_value(dkg_curve, Config),

    DKGResults = miner_ct_utils:pmap(
                   fun(Miner) ->
                           ct_rpc:call(Miner, miner_consensus_mgr, initial_dkg,
                                       [InitialTransactions, Addresses, N, Curve],
                                       timer:seconds(60))
                   end, Miners),
    ?assertEqual([ok], lists:usort(DKGResults)),
    {comment, DKGResults}.
