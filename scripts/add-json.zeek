##! Additional JSON-logging for Zeek.

module Log;

export {
	## Enables JSON-logfiles for all active streams
	const enable_all_json = T &redef;
	## Enables JSON-logfiles for all filters of a stream
	const enable_all_filters_json = F &redef;
	## Streams not to generate JSON-logfiles for
	const exclude_json: set[Log::ID] = { } &redef;
	## Streams to generate JSON-logfiles for
	const include_json: set[Log::ID] = { } &redef;
	## Path to the additional JSON-logfiles
	const path_json = "" &redef;
	## Rotation interval for JSON-logfiles
	const interv_json = default_rotation_interval &redef;
	## Format of timestamps for JSON-logfiles.
	## See: :zeek:see:`LogAscii::json_timestamps`
	const timestamps_json = "JSON::TS_MILLIS" &redef;
	## Separator for log field scopes.
	## See: :zeek:type:`Log::Filter`
	const scope_sep_json = default_scope_sep &redef;
}

type path_func_type: function(id: Log::ID, path: string, rec: any): string;

# Create a path_func wrapper that appends the "-json" suffix
function make_path_func(orig_path_func: path_func_type): path_func_type
	{
	return function(id: Log::ID, path: string, rec: any): string
		{
		if ( /-json/ in path )
			# As path is set to the previous result of the function, the
			# the "-json" suffix is removed to provide the correct string
			# to the original path_func.
			path = path[:-5];
		local orig_path = orig_path_func(id, path, rec);
		return string_cat(orig_path, "-json");
		};
	}

event zeek_init() &priority=-3
	{
	const config_json = table(
		["use_json"] = "T",
		["json_timestamps"] = timestamps_json);

	local filters_copy = copy(Log::filters);
	for ( [id, filter_name] in filters_copy )
		{
		if ( !(enable_all_json || (id in include_json)) || (id in exclude_json) )
			next; # Ignore unwanted log streams

		if ( !enable_all_filters_json && filter_name != "default" )
			next; # Ignore unwanted filters

		local filter = filters_copy[id, filter_name];
		if ( filter$writer == Log::WRITER_ASCII && "use_json" in filter$config &&
			 filter$config["use_json"] == "T")
			next; # Ignore existing JSON filters

		# Add new filter for JSON output (previously copied)
		filter$name = string_cat(filter$name, "_json");
		filter$writer = Log::WRITER_ASCII;
		if ( filter?$path )
			filter$path = string_cat(path_json, filter$path, "-json");
		if ( filter?$path_func )
			filter$path_func = make_path_func(filter$path_func);
		filter$config = config_json;
		filter$interv = interv_json;
		filter$scope_sep = scope_sep_json;
		Log::add_filter(id, filter);
		}
	}
