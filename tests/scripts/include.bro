#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: ls -l *.log | awk '{print $9}' > out
# @TEST-EXEC: btest-diff out

redef Log::enable_all_json = F;
redef Log::include_json = {DNS::LOG, Conn::LOG, Weird::LOG};
redef Log::exclude_json = {Weird::LOG}; # precedence
