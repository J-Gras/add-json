#
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: ls -l *.log | awk '{print $9}' > out
# @TEST-EXEC: btest-diff out

redef Log::exclude_json = {HTTP::LOG, Weird::LOG, PacketFilter::LOG};
