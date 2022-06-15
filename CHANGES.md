* 2.x.x
  * 2.0.x
    * 2.0.0 - 2022-06-13
      * Rewrite in TypeScript
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