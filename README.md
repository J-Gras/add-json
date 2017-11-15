# Add-JSON

This package provides additional JSON-logging for Bro. By default a JSON log is enabled
for every logging stream (original filename suffixed by `-json`). For further configuration,
the following options are available:

Option                       | Default Value       | Description
-----------------------------|---------------------|-----------------------------------------------
`enable_all_json: bool`      | `T`                 | Enables JSON-logfiles for all active streams
`exclude_json: set[Log::ID]` | `{ }`               | Streams **not** to generate JSON-logfiles for
`include_json: set[Log::ID]` | `{ }`               | Streams to generate JSON-logfiles for
`path_json: string`          | default path        | Path to the additional JSON-logfiles
`interv_json: interval`      | default interval    | Rotation interval for JSON-logfiles
`timestamps_json: string`    | `"JSON::TS_MILLIS"` | Format of timestamps for JSON-logfiles.
`scope_sep_json: string`     | default separator   | Separator for log field scopes.

If, for example, your postprocessing of the files cannot handle dots in field names, you can
add the following to you `local.bro` to replace them with underscores:

    redef Log::scope_sep_json = "_";

For more details on the underlying filter options see:
https://www.bro.org/sphinx/scripts/base/frameworks/logging/main.bro.html#type-Log::Filter

**Note:** The script has been tested with Bro version 2.5.
