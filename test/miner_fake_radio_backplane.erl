-module(miner_fake_radio_backplane).

-behaviour(gen_server).

-include_lib("helium_proto/src/pb/helium_longfi_pb.hrl").

-export([start_link/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
          udp_sock,
          udp_ports
         }).

-define(WRITE_RADIO_PACKET, 16#0).
-define(WRITE_RADIO_PACKET_ACK, 16#80).
-define(READ_RADIO_PACKET, 16#81).
-define(READ_RADIO_PACKET_EXTENDED, 16#82).

-define(FREQUENCY, 915).
-define(TRANSMIT_POWER, 28).
-define(MAX_ANTENNA_GAIN, 6).

start_link(MyPort, UDPPorts) ->
    gen_server:start_link(?MODULE, [MyPort, UDPPorts], []).

init([MyPort, UDPPorts]) ->
    %% create UDP client port
    {ok, Sock} = gen_udp:open(MyPort, [binary, {active, true}, {reuseaddr, true}]),
    {ok, #state{udp_sock=Sock, udp_ports=UDPPorts}}.

handle_call(Msg, _From, State) ->
    lager:warning("unhandled call ~p", [Msg]),
    {reply, error, State}.

handle_cast(Msg, State) ->
    lager:warning("unhandled cast ~p", [Msg]),
    {noreply, State}.

handle_info({udp, UDPSock, _IP, SrcPort, InPacket}, State = #state{udp_sock=UDPSock, udp_ports=Ports}) ->
    Decoded = helium_longfi_pb:decode_msg(InPacket, helium_LongFiReq_pb),
    {_, Uplink} = Decoded#helium_LongFiReq_pb.kind,
    Payload = Uplink#helium_LongFiTxPacket_pb.payload,
    OUI = Uplink#helium_LongFiTxPacket_pb.oui,
    DeviceID = Uplink#helium_LongFiTxPacket_pb.device_id,
    ct:pal("Source port ~p, Ports ~p", [SrcPort, Ports]),
    {SrcPort, OriginLocation} = lists:keyfind(SrcPort, 1, Ports),
    lists:foreach(
        fun({Port, Location}) ->
                Distance = distance(OriginLocation, Location),
                FreeSpacePathLoss = ?TRANSMIT_POWER - (32.44 + 20*math:log10(?FREQUENCY) + 20*math:log10(Distance) - ?MAX_ANTENNA_GAIN - ?MAX_ANTENNA_GAIN),
                case Distance > 32 of
                    true ->
                        ct:pal("NOT sending from ~p to ~p -> ~p km", [OriginLocation, Location, Distance]),
                        ok;
                    false ->
                        ct:pal("sending from ~p to ~p -> ~p km RSSI ~p", [OriginLocation, Location, Distance, FreeSpacePathLoss]),
                        Resp = #helium_LongFiResp_pb{kind={rx, #helium_LongFiRxPacket_pb{payload=Payload, crc_check=true, oui=OUI, rssi=FreeSpacePathLoss, device_id=DeviceID}}},
                        gen_udp:send(UDPSock, {127, 0, 0, 1}, Port, helium_longfi_pb:encode_msg(Resp))
                end
        end,
        lists:keydelete(SrcPort, 1, Ports)
    ),
    {noreply, State};
handle_info(Msg, State) ->
    ct:pal("unhandled info ~p", [Msg]),
    {noreply, State}.

distance(L1, L2) ->
    case vincenty:distance(h3:to_geo(L1), h3:to_geo(L2)) of
        {error, _} ->
            %% An off chance that the points are antipodal and
            %% vincenty_distance fails to converge. In this case
            %% we default to some max distance we consider good enough
            %% for witnessing
            1000;
        {ok, D} ->
            D - hex_adjustment(L1) - hex_adjustment(L2)
    end.

hex_adjustment(Loc) ->
    %% Distance from hex center to edge, sqrt(3)*edge_length/2.
    Res = h3:get_resolution(Loc),
    EdgeLength = h3:edge_length_kilometers(Res),
    EdgeLength * (round(math:sqrt(3) * math:pow(10, 3)) / math:pow(10, 3)) / 2.
