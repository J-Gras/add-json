#
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace ../../../scripts/ %INPUT
# @TEST-EXEC: cat http*.log > out
# @TEST-EXEC: ls -l http* | awk '{print $9}' >> out
# @TEST-EXEC: btest-diff out

function test_path_func(id: Log::ID, path: string, rec: HTTP::Info): string
     {
     return string_cat(path, "-", rec$host);
     }

event zeek_init()
{
	Log::add_filter(HTTP::LOG, [
		$name = "default",
		$path_func = test_path_func]);
}
