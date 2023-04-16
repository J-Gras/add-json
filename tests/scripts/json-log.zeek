#
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace ../../../scripts/
# @TEST-EXEC: for i in `ls *.log | sort`; do printf '>>> %s\n' $i; cat $i; done >> out
# @TEST-EXEC: btest-diff out
