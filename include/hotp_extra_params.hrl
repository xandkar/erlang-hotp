-record(hotp_extra_params,
    { hash_algo = sha :: hotp_hmac:hash_algo()
    , length    = 6   :: integer()  % Number of digits desired
    }).
