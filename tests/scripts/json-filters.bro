#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: cat http*.log > out
# @TEST-EXEC: ls -l http* >> out
# @TEST-EXEC: btest-diff out

redef Log::enable_all_filters_json = T;

event bro_init()
	{
	Log::add_filter(HTTP::LOG, [
		$name = "http-included",
		$path = "http-included"]);
	}

event bro_init()
	{
	const config_json = table(
		["use_json"] = "T",
		["json_timestamps"] = Log::timestamps_json);
	
	Log::add_filter(HTTP::LOG, [
		$name = "http-excluded",
		$path = "http-excluded",
		$config = config_json]);
	}