.PHONY: \
	all \
	compile \
	clean \
	dialyze \
	test

all: travis_ci dialyze

travis_ci: clean compile test

compile:
	@rebar compile

clean:
	@rebar clean

dialyze:
	@dialyzer ebin/*.beam test/*.beam

test:
	@rebar ct
