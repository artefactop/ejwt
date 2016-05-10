%%%-------------------------------------------------------------------
%%% File        : ejwt.erl
%%% Author      : Jose Luis Navarro
%%% Description : encode/decode library for jwt
%%%-------------------------------------------------------------------

-module(ejwt).

-define(HS256, <<"HS256">>).
-define(HS384, <<"HS384">>).
-define(HS512, <<"HS512">>).

-export([encode/2, encode/3, decode/1, decode/2]).

-type key() :: iolist() | binary().

%% ===================================================================
%% Application callbacks
%% ===================================================================

-spec encode(Payload :: list(), Key :: key()) -> binary().

encode(Payload, Key) ->
    encode(Payload, Key, ?HS256).

-spec encode(Payload :: list(), Key :: key(), Algorithm :: binary()) -> binary().

encode(Payload, Key, Algorithm) ->
    Header = [{<<"alg">>, Algorithm}, {<<"typ">>, <<"JWT">>}],
    Hjson = jsx:encode(Header),
    Pjson = jsx:encode(Payload),
    Hb = base64url:encode(Hjson),
    Pb = base64url:encode(Pjson),
    Data = <<Hb/binary, ".", Pb/binary>>,
    Signing = base64url:encode(get_mac(Key, Data, Algorithm)),
    <<Data/binary, ".", Signing/binary>>.

-spec get_mac(Key :: key(), Data :: binary(), Method :: binary()) -> binary().

get_mac(Key, Data, ?HS256) ->
    crypto:hmac(sha256, Key, Data);
get_mac(Key, Data, ?HS384) ->
    crypto:hmac(sha384, Key, Data);
get_mac(Key, Data, ?HS512) ->
    crypto:hmac(sha512, Key, Data).

-spec decode(JWT :: binary()) -> list() | error.

decode(JWT) ->
    decode(JWT, undefined).

-spec decode(JWT :: binary(), Key :: key()) -> list() | error.

decode(JWT, Key) ->
    [Header_segment, Data] = binary:split(JWT, <<".">>),
    [Payload_segment, Crypto_segment] = binary:split(Data, <<".">>),
    Payload = jsx:decode(base64url:decode(Payload_segment)),
    case Key of
        undefined -> Payload;
        _ ->
            Header = jsx:decode(base64url:decode(Header_segment)),
            Signature = base64url:decode(Crypto_segment),
            Signing_input = <<Header_segment/binary, ".", Payload_segment/binary>>,
            Signing = get_mac(Key, Signing_input, proplists:get_value(<<"alg">>, Header)),
            if
                Signature == Signing ->
                    Payload;
                true ->
                    error
            end
    end.
