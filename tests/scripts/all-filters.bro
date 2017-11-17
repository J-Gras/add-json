#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: cat http*.log > out
# @TEST-EXEC: ls -l http*  | awk '{print $9}' >> out
# @TEST-EXEC: btest-diff out

redef Log::enable_all_filters_json = T;

event bro_init()
	{
	Log::add_filter(HTTP::LOG, [
		$name = "http-included",
		$path = "http-included"]);
	}

event bro_init() &priority=-5
	{
	Log::add_filter(HTTP::LOG, [
		$name = "http-excluded",
		$path = "http-excluded"]);
	}
