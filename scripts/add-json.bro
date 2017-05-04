##! Additional JSON-logging for Bro.

module Log;

export {
	## Enables JSON-logfiles for all active streams
	const enable_all_json = T &redef;
	## Streams not to generate JSON-logfiles for
	const exclude_json: set[Log::ID] = { } &redef;
	## Streams to generate JSON-logfiles for
	const include_json: set[Log::ID] = { } &redef;
	## Path to the additional JSON-logfiles
	const path_json = "" &redef;
	## Rotation interval for JSON-logfiles
	const interv_json = default_rotation_interval &redef;
	## Format of timestamps for JSON-logfiles.
	## See: :bro:see:`LogAscii::json_timestamps`
	const timestamps_json = "JSON::TS_MILLIS" &redef;
	## Separator for log field scopes.
	## See: :bro:type:`Log::Filter`
	const scope_sep_json = default_scope_sep &redef;
}

# Wrapper for path_func implementations, appending "-json"
function json_path_func(id: Log::ID, path: string, rec: any): string
	{
	local filter = Log::get_filter(id, "default");
	if ( /-json/ in path )
		path = path[:-5];
	local new_path = filter$path_func(id, path, rec);
	return string_cat(new_path, "-json");
	}

event bro_init() &priority=-3
	{
	const config_json = table(
		["use_json"] = "T",
		["json_timestamps"] = timestamps_json);

	# Add filter for JSON output
	for ( id in Log::active_streams )
		{
		if ( (enable_all_json || (id in include_json)) && (id !in exclude_json) )
			{
			local filter = copy(Log::get_filter(id, "default"));
			filter$name = "default_json";
			filter$writer = Log::WRITER_ASCII;
			if ( filter?$path )
				filter$path = string_cat(path_json, filter$path, "-json");
			if ( filter?$path_func )
				filter$path_func = json_path_func;
			filter$config = config_json;
			filter$interv = interv_json;
			filter$scope_sep = scope_sep_json;
			Log::add_filter(id, filter);
			}
		}
	}
