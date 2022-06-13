# little-log-scan - Scan log files for suspicious strings

Small tool that scans log files for suspicious strings.
Intended for webserver logs, but usable with any text-based log file.
Lines are read from standard input, and any matches are written to standard output.

## Usage
* Linux - `./little-log-scan.sh [options]`
* Windows - `./little-log-scan.bat [options]`
* Anything - `node ./little-log-scan.mjs [options]`

## Arguments
TODO

## Output Formats
TODO

## Rules
TODO

## Decoders
TODO

## Requirements
TODO

### Please note that this is NOT security software!
This script is a simple tool intended for research and forensic purposes.
There is no gaurantee of accuracy or completeness.
False positives and false negatives are expected.
The authors are not responsible for any negative impact due to use of this software.


### Important note regarding use of regular expressions:
This script is highly regex-based, which introduces certain weaknesses.
Effort has been made to detect and handle anomolous input, but there is a limit to what can be done with regular expressions.
The main things to be aware of are:
* No protection against regex DOS. A carefully-crafted input can consume extreme amounts of CPU and memory resources.
* Minimal protection against log injection. As this script is not (currently) aware of log formats, there is no good way to detect this attack. What protection *does* exist is format-checking and treating all input as untrusted.

*This is an upgraded version of the gist available [here](https://gist.github.com/warriordog/840e4a3e98c01987a32221b13233383a). While that version will continue to function, I recommend using this one instead. It has many upgrades and improvements.*
