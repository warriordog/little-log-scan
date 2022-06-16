# little-log-scan - Scan log files for suspicious strings
Small tool that scans log files for suspicious strings.
Intended for webserver logs, but usable with any text-based log file.
Lines are read from standard input, and any matches are written to standard output.

![npm version](https://badge.fury.io/js/little-log-scan.svg)
![GitHub Release Date](https://img.shields.io/github/release-date/warriordog/little-log-scan)

## Usage
* Through npx: `npx little-log-scan [options]`
* Through npm: `npm install little-log-scan && npm run cli -- [options]`
* Standalone:
  * Linux - `./little-log-scan.sh [options]`
  * Windows - `./little-log-scan.bat [options]`
  * Anything - `node ./bin/cli [options]`

## Examples
* Standard usage (default settings): `cat some.log | little-log-scan`
* Only scan for vulnerabilities: `cat some.log | little-log-scan --include=Vulnerability/`
* Ignore Log4Shell exploit: `cat some.log | little-log-scan --exclude=CVE-2021-44228,CVE-2021-45046`
* Scan for vulnerabilities excluding WordPress plugins: `cat some.log | litle-log-scan --include=Vulnerability/ --exclude=Vulnerability/Wordpress/plugin/`
* Output in TSV format: `cat some.log | little-log-scan --tsv > findings.tsv`
* Include the raw match for manual decoding: `cat some.log | little-log-scan --raw=Y > findings_with_raw.log`

## Arguments

The following options are supported. Any with an "argument" field should have a value set using the form `--option=value`.

| Option       | Arguments  | Default    | Description                                                                   |
|--------------|------------|:-----------|:------------------------------------------------------------------------------|
| --help       |            |            | Print help and exit.                                                          |
| --version    |            |            | Print version and exit.                                                       |
| --list-rules |            |            | List all rules that are included by the specified include/exclude patterns.   |
| --tsv        |            | No (unset) | Output in TSV (tab-delimited) format.                                         |
| --cleaned    | Y/N        | Y (yes)    | Include the entire cleaned, decoded line in the output.                       |
| --raw        | Y/N        | N (no)     | Include the entire raw, un-decoded line in the output.                        |
| --include    | pattern(s) | Everything | Patterns to include rules (comma separated). Only matching rules will be run. |
| --exclude    | pattern(s) | None       | Patterns to exclude rules (comma separated). Overrides --include option.      |

## Output Formats
Depending on flags, output may contain the following components:
* __Finding__: Name of the rule that matched the output.
* __Index__: Index (line number) of the line that was matched. This is counted by lines received as piped input, not lines in the original file.
* __Match__: Portion of the line that was detected. This is automatically decoded / deobfuscated, if possible.
* __Line__: Entire content of the matched line. This is automatically decoded / deobfuscated, if possible.
* __Raw__: Same as "line", but NOT decoded. Only the standard sanitization is applied.

Example output formats:
* "TSV" means that `--tsv` is set.
* "Raw" means that `--raw` is set to `y`.
* "Clean" means that `--clean` is set to `y` or unset (default).

| TSV | Raw | Clean | Format                                        | Notes                                |
|-----|-----|-------|-----------------------------------------------|--------------------------------------|
| X   | X   | X     | [Finding]\t[Index]\t[Match]\t[Line]\t[Raw]    |                                      |
| X   |     | X     | [Finding]\t[Index]\t[Match]\t[Line]           |                                      |
|     | X   | X     | [Finding]: [Index] {[Match]} {[Line]} {[Raw]} | Index is left-padded to 9 characters |
|     |     | X     | [Finding]: [Index] {[Match]} {[Line]}         | Index is left-padded to 9 characters |
| X   | X   |       | [Finding]\t[Index]\t[Match]\t[Raw]            |                                      |
| X   |     |       | [Finding]\t[Index]\t[Match]                   |                                      |
|     | X   |       | [Finding]: [Index] {[Match]} {[Raw]}          | Index is left-padded to 9 characters |
|     |     |       | [Finding]: [Index] {[Match]}                  | Index is left-padded to 9 characters |

## Rules
Rules form the main logic of little-log-scan. Rules consist of a regular expression to "match" the rule, along with optional logic to further decode or analyze the match. Some rules detect known inputs, while others are heuristic. Heuristic rules are typically labeled as "/generic" for easy filtering. Rules are split into several categories and subcategories:

### Vulnerabilities (`Vulnerability/`)
These rules detect attempts to exploit known software vulnerabilities. Whenever possible, they are arranged hierarchically to allow filtering based on specific software / versions.
TODO subcategories
* Vulnerability/generic/traversal
* Vulnerability/Axis Camera RCE
* Vulnerability/CKEditor/v4.4.7/RCE
* Vulnerability/ColdFusion/v10/Credential Disclosure
* Vulnerability/F5 BIG-IP/CVE-2022-1388 RCE
* Vulnerability/FortiOS/CVE-2018-13379 Path Traversal
* Vulnerability/GeoVision Camera/Auth Bypass
* Vulnerability/GeoVision Camera/Double Free
* Vulnerability/GeoVision Camera/RCE
* Vulnerability/GeoVision Camera/Stack Overflow
* Vulnerability/GeoVision Camera/Unauthorized Access
* Vulnerability/GNU Bash/v4.3 bash43-025/CVE-2014-7169 RCE (Shellshock 2)
* Vulnerability/GNU Bash/v4.3/CVE-2014-6271 RCE (Shellshock)
* Vulnerability/HiSilicon DVR/RCE
* Vulnerability/Log4j/v2.16.0/CVE-2021-44228 RCE (Log4Shell)
* Vulnerability/Log4j/v2.17.0/CVE-2021-45046 RCE (Log4Shell 2)
* Vulnerability/PHPCMS/Auth Bypass
* Vulnerability/PHPUnit/v4.8.28/CVE-2017-9841 RCE
* Vulnerability/ThinkCMF/RCE
* Vulnerability/TVT DVR/RCE
* Vulnerability/Wordpress/plugin/appointment-booking-calendar/v1.1.24/SQLi
* Vulnerability/Wordpress/plugin/aspose-doc-exporter/v1.0/Arbitrary File Download
* Vulnerability/Wordpress/plugin/cherry-plugin/v1.2.6/Arbitrary File Disclosure
* Vulnerability/Wordpress/plugin/db-backup/v4.5/CVE-2014-9119 Arbitrary File Disclosure
* Vulnerability/Wordpress/plugin/google-document-embedder/v2.4.6/Arbitrary File Disclosure
* Vulnerability/Wordpress/plugin/google-document-embedder/v2.5.14/SQLi
* Vulnerability/Wordpress/plugin/google-mp3-audio-player/v1.0.11/Arbitrary File Disclosure
* Vulnerability/Wordpress/plugin/mac-dock-gallery/v2.7/Arbitrary File Upload
* Vulnerability/Wordpress/plugin/mac-dock-gallery/v2.9/Arbitrary File Disclosure
* Vulnerability/Wordpress/plugin/mini-mail-dashboard-widget/v1.36/Remote File Inclusion
* Vulnerability/Wordpress/plugin/multi-meta-box/v1.0/SQLi
* Vulnerability/Wordpress/plugin/mygallery/v1.4b4/CVE-2007-2426 Remote File Inclusion
* Vulnerability/Wordpress/plugin/recent-backups/v0.7/Arbitrary File Disclosure
* Vulnerability/ZeroShell/v3.9.0/CVE-2019-12725 Command Injection
* Vulnerability/ZeroShell/v3.9.3/CVE-2020-29390 Command Injection
* Vulnerability/ZyXEL/CVE-2020-9054 RCE

### Payloads (`Payload/`)
These rules *attempt* to detect malicious payloads. They are mostly heuristic and generate a lot of noise.
* Payload/Downloader/curl
* Payload/Downloader/generic
* Payload/Downloader/netcat
* Payload/Downloader/wget
* Payload/Eval
* Payload/Executable/generic
* Payload/Executable/Linux
* Payload/Executable/Windows
* Payload/Script/PHP
* Payload/Script/Shebang
* Payload/Shell/Linux
* Payload/Shell/Windows

### Malware (`Malware/`)
These rules detect communication patterns of known and suspected malware. Successful responses can indicate that the target machine is already compromised.
* Malware/Mozi
* Malware/Webshell/generic
* Malware/Webshell/Sp3ctra

### Obfuscation (`Obfuscation/`)
These rules detect common techniques used to hide malicious activity.
* Obfuscation/Interpolation

## Decoders
Threat actors frequently use encoding, obfuscation, and other tricks to hide their actions. Little-log-scan includes several routines to automatically detect and decode common techniques used to bypass detection. Additionally, common non-malicious encoding is reversed to simplify other parts of the application. All cleaners work iteratively to decode nested obfuscation, even of multiple different types. The following decoders (called "cleaners" in the code) are included:

### Malicious Obfuscation
These decoders work against techniques that are known to be in use by threat actors. Several encodings are supported:
* Log4j expressions of the forms `${foo:-A}`, `${foo:bar:-A}`, `${::-A}`, and similar (all decode to "A")
* Log4j expressions of the forms `${lower:A}` (decodes to "a") and `${upper:a}` (decodes to "A") 
* Log4j expressions of the forms `$$lower{A}` (decodes to "a") and `$$upper{a}` (decodes to "A")
* Log4j expressions of the form `${base64:==Zm9v}` (decodes to "foo")
* The string `${IFS}` used to encode a space on many embedded devices made by TVT
* Base64-encoded strings piped to `md5sum` - for example `echo -n Zm9v | md5sum` (decodes to "foo")

### Standard Encodings
These decoders work for encodings that are a part of standard communication protocols. This allows other rules to more easily scan the internal data being passed between systems.
* Base64-encoded HTTP "Basic" Authorization header - this allows scanning strings passed as the username or password
* URL encoding (percent sign + hex digits) - `hi%21` decodes to `hi!`


### Other
* All slashes are aligned to be forward slashes. This is done less as a deobfuscation technique and more as an optimization to simplify all the regular expressions.


## Requirements
NodeJS 16 or newer is required to run little-log-scan. Any compatible operating system and environment should work. 

## Security Concerns
While care has been taken to develop this tool in a secure manner, there are still some important security concerns when working with untrusted data. 

### Please note that this is NOT security software!
This script is a simple tool intended for research and forensic purposes.
There is no guarantee of accuracy or completeness.
False positives and false negatives are expected.
The authors are not responsible for any negative impact due to use of this software.


### Important note regarding use of regular expressions:
This script is highly regex-based, which introduces certain weaknesses.
Effort has been made to detect and handle anomalous input, but there is a limit to what can be done with regular expressions.
The main things to be aware of are:
* No protection against regex DOS. A carefully-crafted input can consume extreme amounts of CPU and memory resources.
* Minimal protection against log injection. As this script is not (currently) aware of log formats, there is no good way to detect this attack. What protection *does* exist is format-checking and treating all input as untrusted.

### Security Model
Design Considerations:
* **Memory-safe Language** - This tool is developed in TypeScript, which is a memory-safe language. This completely eliminates a large attack surface of potential memory bugs that would occur if using a lower-level language. This has tradeoffs for performance, but this is not intended to be a high-performance application.
* **Input Is Untrusted** - All input data is treated as malicious. Nothing read from any input is trusted.
* **Global Output Sanitization** - All output goes through a sanitization routine that strips any non-ascii-printable characters. 
* **No File IO** - little-log-scan is intended to be used with piped input and output. This eliminates the risk of any file exploits that could occur by deriving filenames from untrusted data. If using the API, the user assumes all responsibility for safely recording results. 

Risks:
* **Regular Expressions** - As described above, using regular expressions carries certain risks. Additionally, some common mitigations (such as timeouts) are not possible in the V8 runtime.

---

*An early version of this tool was once shared as a [gist](https://gist.github.com/warriordog/840e4a3e98c01987a32221b13233383a). While it will continue to function, I recommend using little-log-scan (this repository) instead. It has many upgrades and improvements over the original prototype.*
