-module(hotp_secret).

-export(
    [ new/0
    , new/1
    ]).

-spec new() ->
    binary().
new() ->
    new(sha).

-spec new(hotp_hmac:hash_algo()) ->
    binary().
new(HashAlgo) ->
    NumOfBytes = num_of_bytes_needed_for_hash_algo(HashAlgo),
    crypto:strong_rand_bytes(NumOfBytes).

num_of_bytes_needed_for_hash_algo(HashAlgo) ->
    case HashAlgo
    of  sha    -> 20
    ;   sha256 -> 32
    ;   sha512 -> 64
    end.
