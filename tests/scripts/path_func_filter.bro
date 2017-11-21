#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: cat http*.log > out
# @TEST-EXEC: ls -l http*  | awk '{print $9}' >> out
# @TEST-EXEC: btest-diff out

redef Log::enable_all_filters_json = T;

function test_path_func(id: Log::ID, path: string, rec: HTTP::Info): string
     {
     return string_cat(path, "-filter-", rec$host);
     }

event bro_init()
	{
	Log::add_filter(HTTP::LOG, [
		$name = "http-filter",
		$path_func = test_path_func]);
	}
