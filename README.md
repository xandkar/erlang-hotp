[![Build Status](https://travis-ci.org/xandkar/erlang-hotp.svg?branch=master)](https://travis-ci.org/xandkar/erlang-hotp)

HOTP
====

Erlang adaptation of HMAC-Based One-Time Password Algorithm, as described in
[RFC 4226].

[RFC 4226]: https://tools.ietf.org/html/rfc4226

Usage
-----

Simplest example:

```erlang
1> Secret = hotp_secret:new().
<<104,212,164,165,146,193,202,163,7,141,26,71,82,17,133,
  95,108,68,35,130>>
2>
2> hotp:cons(Secret, 0).
130575
3>
```

See tests for more.
