REBAR := rebar3

.PHONY: \
	all \
	compile \
	clean \
	dialyze \
	test

all:
	$(MAKE) compile
	$(MAKE) dialyze
	$(MAKE) test

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

dialyze:
	@$(REBAR) do dialyzer
	@$(REBAR) as test do dialyzer

test:
	@$(REBAR) as test do eunit,cover
