# Add-JSON

This package provides additional JSON-logging for Zeek. By default a JSON log is enabled for every
logging stream (original filename suffixed by `-json`). For further configuration, the following
options are available:

Option                       | Default Value       | Description
-----------------------------|---------------------|---------------------------------------------------
`enable_all_json: bool`      | `T`                 | Enables JSON-logfiles for all active streams
`enable_all_filters_json`    | `F`                 | Enables JSON-logfiles for all filters of a stream
`exclude_json: set[Log::ID]` | `{ }`               | Streams **not** to generate JSON-logfiles for
`include_json: set[Log::ID]` | `{ }`               | Streams to generate JSON-logfiles for
`path_json: string`          | default path        | Path to the additional JSON-logfiles
`interv_json: interval`      | default interval    | Rotation interval for JSON-logfiles
`timestamps_json: string`    | `"JSON::TS_MILLIS"` | Format of timestamps for JSON-logfiles.
`scope_sep_json: string`     | default separator   | Separator for log field scopes.

If, for example, the postprocessing of JSON-logs cannot handle dots in field names, the following can
be added to `local.zeek`, to replace dots with underscores:

    redef Log::scope_sep_json = "_";

For more details on the underlying filter options see [Zeek's documentation
](https://docs.zeek.org/en/current/scripts/base/frameworks/logging/main.zeek.html#type-Log::Filter)
of the Logging Framework.

## Testing

Tests using Zeek's `btest` are available in a separate branch `tests`. The tests can be run manually
or automated during installation (`zkg install add-json --version tests`).

## Custom Logs

The add-json package sets up additional filters for the configured logs during initialization. As
the corresponding `zeek_init` event handler is executed with a priority of -3, everything (streams
and filters) setup with a _higher_ priority than -3 will be considered by the script.
