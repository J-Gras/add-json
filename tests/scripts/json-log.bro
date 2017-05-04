#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/
# @TEST-EXEC: cat *.log > out
# @TEST-EXEC: btest-diff out