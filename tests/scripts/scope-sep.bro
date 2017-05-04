#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: cat *.log > out
# @TEST-EXEC: btest-diff out

redef Log::scope_sep_json = "_";