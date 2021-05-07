# icetrust canary mode

# What is this?
"Canary" mode can be used by project owners to download and verify project files on a regular basis
to detect supply chain attacks. This mode uses JSON configuration files that contain information
about a project being verified and can produce JSON output to be used in automation.

Sample files, input and output schemas can be found here:
- [Input schema](icetrust/data/canary_input.schema.json)
- [Output schema](icetrust/data/canary_output.schema.json)
- [Sample input files](test_data/canary_input)
- [Sample output files](test_data/canary_input)

# How to use 
To use this mode, you must create a JSON file that follows the defined schema then pass it to 
the tool via command line:
```
icecrust canary config.json
```

If you want to output the details to a JSON file, do the following:
```
icecrust canary --output-json-file output.json config.json
```

The various verification options and details are the same as the main utility, except that
canary mode will download the various files involved into a temporary directly before
verification.

## Example dashboards
This mode can be used in automation as a scheduled job to run the checks. 
There are two examples of what this looks like in practice:
- [icetrust_dashboard_example](https://github.com/nightwatchcybersecurity/icetrust_dashboard_example) -
  a single-page dashboard showing verification status, based on Jekyll and
  some basic scripting
- [icetrust_uptime_example](https://github.com/nightwatchcybersecurity/icetrust_uptime_example) -
  an "uptime" dashboard, similar to uptime status pages used by regular
  websites. Based on some scripting and the "upptime" project.

## Live Demos  
Live demos can be viewed here:
- [icetrust_dashboard.nightwatchcybersecurity.com](https://icetrust_dashboard.nightwatchcybersecurity.com)
- [icetrust_uptime.nightwatchcybersecurity.com](https://icetrust_uptime.nightwatchcybersecurity.com)

## Reporting bugs and feature requests
Please use the GitHub issue tracker to report issues or suggest features:
https://github.com/nightwatchcybersecurity/icetrust

You can also send emai to ***research /at/ nightwatchcybersecurity [dot] com***

