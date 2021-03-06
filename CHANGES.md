* 2.x.x
  * 2.0.x
    * 2.3.0 - xxxx-xx-xx
      * `--rule-desc`, `--rule-cve`, and `--tsv-header` are on by default
      * Raw output is moved to the end of the line
      * Split `Payload/Downloader/generic` into `Payload/Downloader/generic/Windows` and `Payload/Downloader/generic/Linux`
      * Add strings from https://lolbas-project.github.io/
        * `Payload/Downloader/generic/Windows`
        * `Payload/Execute/Tools/bitsadmin`
        * `Payload/Execute/Tools/certoc`
        * `Payload/Execute/Tools/squirrel`
        * `Payload/Execute/Tools/url.dll`
        * `Payload/Execute/Tools/zipfldr.dll`
        * `Payload/Downloader/bitsadmin`
        * `Payload/Downloader/certoc`
        * `Payload/Downloader/xwizard`
        * `Payload/Downloader/squirrel`
      * Split `Payload/generic/Eval` into `Payload/Execute/Tools/generic/Windows`, `Payload/Execute/Tools/generic/Linux`, and `Payload/Execute/Functions/generic`
      * Rename `Payload/Executable/*` to `Payload/Execute/Extensions/*`
      * Add `Payload/Stealth/Log Tampering`
      * Add `Payload/Stealth/Hiding`
      * Add `Vulnerability/Concrete/v8.5.7/*`
      * Add `Vulnerability/Prison Management System/v1.0/*`
      * Add `Vulnerability/Wordpress/plugin/simple-ads-manager/v2.9.8.125/CVE-2017-20095 Object Injection`
      * Add `Vulnerability/Wordpress/plugin/new-stat-plugin/v1.2.4/CVE-2017-20094 XSS`
      * Add `Vulnerability/Wordpress/plugin/user-photo/v0.9.4/CVE-2013-1916 Arbitrary File Upload`
      * Match more filenames in `Malware/Mozi`
      * Match more script runtimes in `Payload/Shell/Windows`
      * Fix overzealous matching in `Payload/Downloader/generic`
      * Simplify `Payload/Shell/Linux`, `Payload/Shell/Windows`, and `Payload/Execute/Functions/generic` by using `/b` at the end
      * Simplify `Vulnerability/generic/traversal` regex by only matching the part with . and /
    * 2.2.0 - 2022-06-17
      * Emit TSV header
      * Emit rule information
      * Update rule metadata
      * More permissive regex for `Payload/Downloader/wget`, `Payload/Downloader/curl`, and `Payload/Downloader/nc`
      * Fix `Malware/Mozi`
      * Rename `Payload/Eval` to `Payload/generic/Eval`
      * Refactor `Scanner` system to be more modular
      * Refactor version info into separate `version.ts` file
    * 2.1.5 - 2022-06-15
      * Enable standalone builds
    * 2.1.4 - 2022-06-15
      * Fix missing newline in output of `--list-rules`
      * Normalize `/generic` rules
      * Rename `Exploit/Traversal` to `Vulnerability/generic/traversal`
    * 2.1.3 - 2022-06-15
      * Fix bin file to allow running through npx (part 3)
    * 2.1.2 - 2022-06-15
      * Fix bin file to allow running through npx (again)
    * 2.1.1 - 2022-06-15
      * Fix bin file to allow running through npx
    * 2.1.0 - 2022-06-15
      * --list-args respects --include and --exclude
      * Fix typo in "Vulnerability/Wordpress/plugin/db-backup/v4.5/CVE-2014-9119 Arbitrary File Disclosure"
    * 2.0.0 - 2022-06-15
      * Rewrite in TypeScript
      * New CLI system
      * Use `process.stdout` instead of `Console`
      * Exit cleanly if stdout is closed (this allows piping to `head` or `tail`)
      * Fix regex in HTTP Basic decoder
      * Fix regex in Vulnerability/CKEditor/v4.4.7/RCE
      * Cleanup: remove unneeded escapes from regex
* 1.x.x
  * 1.4.x
    * 1.4.0 - 2022.06-12
      * Add --version command
      * Reorder cleaners based on expected order of appearance
      * Cleanup: Normalize rule names
        * Remove pluralization
        * Add versions wherever possible
        * Split Payload/Executable into Generic, Windows, and Linux variants
      * Cleanup: Improve command argument parsing
      * Cleanup: Add necessary documentation for public release
      * Cleanup: Add code license
      * Cleanup: Remove dead and commented code
  * 1.3.x
    * 1.3.0 - 2022-06-11
      * Add option to disable writing full match
      * Rework output options to be true/false flags
      * Decode HTTP Authorization header
      * Decode calls to md5sum
      * Add Vulnerability/TVT DVR RCE
      * Add Payload/Downloader/generic
      * Add Payload/Scripts/PHP
      * Add Payload/Scripts/Shebang
      * Fix missing sanitization
  * 1.2.x
    * 1.2.1 - 2022-06-10 
      * Fix overzealous GeoVision rules
      * Fix Log4J base64 decoding
      * Decode Log4J /Command/Base64/ format
      * Decode Log4J encoded symbols (ex ${lower::}, ${env:BARFOO:-:})
    * 1.2.0 - 2022-06-10
      * Include/exclude rules
      * More specific vuln / malware signatures
      * Improvements to Exploit/Traversal, Malware/Webshell/Generic, and Payload/Executables
      * Fixes to Log4J obfuscation decoding
  * 1.1.x
    * 1.1.1 - 2022-06-09
      * Detect wget, curl, and netcat
    * 1.1.0 - 2022-06-08
      * Add CLI output
      * Implement tab-delimited output
      * Implement verbose output
  * 1.0.x
    * 1.0.0 - Early development, no changelog available