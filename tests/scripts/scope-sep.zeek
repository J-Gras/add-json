#
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: for i in `ls *.log | sort`; do printf '>>> %s\n' $i; cat $i; done >> out
# @TEST-EXEC: btest-diff out

redef Log::scope_sep_json = "_";