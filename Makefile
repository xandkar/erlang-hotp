.PHONY: \
	all \
	compile \
	clean \
	dialyze \
	test

all: clean compile test dialyze

compile:
	@rebar compile

clean:
	@rebar clean

dialyze:
	@dialyzer ebin/*.beam test/*.beam

test:
	@rebar ct
