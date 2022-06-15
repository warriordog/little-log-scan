/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * Scans log files for suspicious strings.
 * Intended for webserver logs, but usable with any text-based log file.
 *
 * Please note that this is NOT security software!
 * This script is a simple tool intended for research and forensic purposes.
 * There is no gaurantee of accuracy or completeness.
 * False positives and false negatives are expected.
 * The authors are not responsible for any negative impact due to use of this software.
 *
 * Important note regarding use of regular expressions:
 * This script is highly regex-based, which introduces certain weaknesses.
 * Effort has been made to detect and handle anomolous input, but there is a limit to the capabilities of V8's RegEx engine.
 * The main things to be aware of are:
 * * No protection against regex DOS. A carefully-crafted input can consume extreme amounts of CPU and memory resources.
 * * Minimal protection against log injection. As this script is not (currently) aware of log formats,
 *      there is no good way to detect this attack. What protection *does* exist is format-checking and treating all
 *      input as untrusted.
 *
 * Author:      Hazel Koehler
 * Version:     1.4.0
 * Modified:    2022-06-12
 *
 * Changes:
 * 1.4.0        2022.06-12      Add --version command
 *                              Reorder cleaners based on expected order of appearance
 *                              Cleanup: Normalize rule names
 *                                  Remove pluralization
 *                                  Add versions wherever possible
 *                                  Split Payload/Executable into Generic, Windows, and Linux variants
 *                              Cleanup: Improve command argument parsing
 *                              Cleanup: Add necessary documentation for public release
 *                              Cleanup: Add code license
 *                              Cleanup: Remove dead and commented code
 * 1.3.0        2022-06-11      Add option to disable writing full match
 *                              Rework output options to be true/false flags
 *                              Decode HTTP Authorization header
 *                              Decode calls to md5sum
 *                              Add Vulnerability/TVT DVR RCE
 *                              Add Payload/Downloader/generic
 *                              Add Payload/Scripts/PHP
 *                              Add Payload/Scripts/Shebang
 *                              Fix missing sanitization
 * 1.2.1        2022-06-10      Fix overzealous GeoVision rules
 *                              Fix Log4J base64 decoding
 *                              Decode Log4J /Command/Base64/ format
 *                              Decode Log4J encoded symbols (ex ${lower::}, ${env:BARFOO:-:})
 * 1.2.0        2022-06-10      Include/exclude rules
 *                              More specific vuln / malware signatures
 *                              Improvements to Exploit/Traversal, Malware/Webshell/Generic, and Payload/Executables
 *                              Fixes to Log4J obfuscation decoding
 * 1.1.1        2022-06-09      Detect wget, curl, and netcat
 * 1.1.0        2022-06-08      Add CLI arguments
 *                              Implement tab-delimited output
 *                              Implement verbose output
 * 1.0.x        2021-12-xx      Early development, no changelog
 */

import * as readline from 'node:readline';

/**
 * @typedef {object} Rule
 * @property {string} name
 * @property {(cleaned: string, raw: string) => (IterableIterator<RegExpMatchArray>)} match
 * @property {(match: RegExpMatchArray, cleanedLine: string, rawLine: string) => string} [decode]
 */

/**
 * @typedef {(line: string) => string} Cleaner
 */

/**
 * @typedef {(string: string) => string} Sanitizer
 */

const escapes = {
    '\x00': '\\0',
    '\x09': '\\t',
    '\x0A': '\\n',
    '\x0D': '\\r',
};

/** @type {Sanitizer[]} */
const sanitizers = [
    // Escape special characters
    // From https://stackoverflow.com/a/24231346
    string => string.replace(/[^ -~]/g, match => escapes[match] || `\\u{${match.charCodeAt(0).toString(16).toUpperCase(0)}}`)
];

/** @type {Rule[]} */
const allRules = [
    {
        // Expanded list from https://stackoverflow.com/a/4669755
        // 2022-06-10: URLs can contain []
        name: 'Exploit/Traversal',
        match: cleaned => cleaned.matchAll(/[A-Za-z0-9\-._~!$&'()*+,;=:@\/?\[\]]*\/\.\.\/[A-Za-z0-9\-._~!$&'()*+,;=:@\/?\[\]]*/g)
    },

    {
        name: 'Payload/Script/PHP',
        match: cleaned => cleaned.matchAll(/<(?:\??php\b|\?=)/gi)
    },
    {
        name: 'Payload/Script/Shebang',
        match: cleaned => cleaned.matchAll(/#!\/?(?:[\w\.\-]+\/)*\w+\s/gi)
    },
    {
        name: 'Payload/Shell/Linux',
        match: cleaned => cleaned.matchAll(/\b(?:chmod|bash|sudo|echo|cat)(?=[\s<>|&])/gi)
    },
    {
        name: 'Payload/Shell/Windows',
        match: cleaned => cleaned.matchAll(/\b(?:powershell|cmd|echo|jscript|cscript)(?=[\s<>|&])/gi)
    },
    {
        name: 'Payload/Eval',
        match: cleaned => cleaned.matchAll(/\b(?:exec|eval)(?=[\s(])/gi)
    },
    {
        name: 'Payload/Executable/Generic',
        match: cleaned => cleaned.matchAll(/\.(?:py|class|jar|war|ear|rb)\b/gi)
    },
    {
        name: 'Payload/Executable/Windows',
        match: cleaned => cleaned.matchAll(/\.(?:bat|cmd|ps[12]|vbs|vba|lnk)\b/gi)
    },
    {
        name: 'Payload/Executable/Linux',
        match: cleaned => cleaned.matchAll(/\.(?:sh)\b/gi)
    },
    {
        name: 'Payload/Downloader/generic',
        match: cleaned => cleaned.matchAll(/\b(?:wget|curl|nc|Net\.WebClient|Invoke-WebRequest|bitsadmin)\b/gi)
    },
    {
        name: 'Payload/Downloader/netcat',
        match: cleaned => cleaned.matchAll(/\bnc(?:\s*-\w\s?[\w:-]*)*\s+\w+(?:\.\w+)*\s+\d+-?\d*/gi)
    },
    {
        name: 'Payload/Downloader/wget',
        match: cleaned => cleaned.matchAll(/\bwget(?:\s+-\w\s?[\w:\/\\\.\-_%]*|\s+--[\w_\-]+=[\w:\/\\\.\-_%]+)*\s+[\w:\/\\\.\-_%]+/gi)
    },
    {
        name: 'Payload/Downloader/curl',
        match: cleaned => cleaned.matchAll(/\bcurl(?:\s+-{1,2}[\w\-]+\s?[\w:\/\\\.\-_%]*)*\s+[\w:\/\\\.\-_%]+/gi)
    },

    {
        name: 'Obfuscation/Interpolation',
        match: cleaned => cleaned.matchAll(/\$+\{[\w:-]*\w+[\w:-]*\}/g)
    },

    {
        // See https://packetstormsecurity.com/files/130807/Ckeditor-4.4.7-Shell-Upload-Cross-Site-Scripting.html
        name: 'Vulnerability/CKEditor/v4.4.7/RCE',
        match: cleaned => cleaned.matchAll(/\bf?ckeditor[\/\\](?:editor|_?samples)[\/\\(?:plugins|php|filemanager)]/gi)
    },
    {
        // See https://github.com/tothi/pwn-hisilicon-dvr/blob/master/README.adoc
        name: 'Vulnerability/HiSilicon DVR/RCE',
        match: cleaned => cleaned.matchAll(/\/mnt\/mtd\/Config\/Account1/gi)
    },
    {
        // See https://gist.github.com/code-machina/bae5555a771062f2a8225fd4731ae3f7
        name: 'Vulnerability/FortiOS/CVE-2018-13379 Path Traversal',
        match: cleaned => cleaned.matchAll(/\/remote\/fgt_lang\?/gi)
    },
    {
        // See https://blog.karatos.in/a?ID=01350-dad9c8fa-17e5-403c-9d7c-d26d82e59ec9
        name: 'Vulnerability/PHPCMS/Auth Bypass',
        match: cleaned => cleaned.matchAll(/\/api\.php\?[\w%_\.\-=&\\\/]*cachefile=[\w%_\.\-=&\\\/]*/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/39342
        name: 'Vulnerability/Wordpress/plugin/appointment-booking-calendar/v1.1.24/SQLi',
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin-ajax\.php\?[\w%_\.\-=&\\\/]*action=cpabc_appointments_calendar_update[\w%_\.\-=&\\\/]*/gi)
    },
    {
        // See https://packetstormsecurity.com/files/136627/WordPress-Multiple-Meta-Box-1.0-SQL-Injection.html
        // See https://gist.github.com/nikcub/9a4d68827e3770587287c254cbf7361a
        name: 'Vulnerability/Wordpress/plugin/multi-meta-box/v1.0/SQLi',
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin\.php\?[\w%_\.\-=&\\\/]*page=multi_metabox_listing[\w%_\.\-=&\\\/]*/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/36559
        name: 'Vulnerability/Wordpress/plugin/aspose-doc-exporter/v1.0/Arbitrary File Download',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/aspose-doc-exporter\/aspose_doc_exporter_download\.php/gi)
        // To capture more, add \?[\w%_\.\-=&\\\/]*file=[\w%_\.\-=&\\\/]*
    },
    {
        // See https://www.exploit-db.com/exploits/35378
        // See https://nvd.nist.gov/vuln/detail/CVE-2014-9119
        name: 'Vulneravility/Wordpress/plugin/db-backup/v4.5/CVE-2014-9119 Arbitrary File Disclosure',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/db-backup\/download\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/23970
        name: 'Vulnerability/Wordpress/plugin/google-document-embedder/v2.4.6/Arbitrary File Disclosure',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/google-document-embedder\/libs\/pdf\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/35371
        name: 'Vulnerability/Wordpress/plugin/google-document-embedder/v2.5.14/SQLi',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/google-document-embedder\/view\.php/gi)
    },
    {
        // See https://wpscan.com/vulnerability/90034817-dee7-40c9-80a2-1f1cd1d033ee
        name: 'Vulnerability/Wordpress/plugin/cherry-plugin/v1.2.6/Arbitrary File Disclosure',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/cherry-plugin\/admin\/import-export\/download-content\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/35460
        name: 'Vulnerability/Wordpress/plugin/google-mp3-audio-player/v1.0.11/Arbitrary File Disclosure',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/google-mp3-audio-player\/direct_download\.php/gi)
    },
    {
        // See https://www.tenable.com/plugins/nessus/62205
        name: 'Vulnerability/Wordpress/plugin/mac-dock-gallery/v2.9/Arbitrary File Disclosure',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mac-dock-gallery\/macdownload\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/19056
        name: 'Vulnerability/Wordpress/plugin/mac-dock-gallery/v2.7/Arbitrary File Upload',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mac-dock-gallery\/upload-file\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/17868
        name: 'Vulnerability/Wordpress/plugin/mini-mail-dashboard-widget/v1.36/Remote File Inclusion',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mini-mail-dashboard-widgetwp-mini-mail\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/3814
        name: 'Vulnerability/Wordpress/plugin/mygallery/v1.4b4/CVE-2007-2426 Remote File Inclusion',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mygallery\/myfunctions\/mygallerybrowser\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/37752
        name: 'Vulnerability/Wordpress/plugin/recent-backups/v0.7/Arbitrary File Disclosure',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/recent-backups\/download-file\.php/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/25305
        name: 'Vulnerability/ColdFusion/v10/Credential Disclosure',
        match: cleaned => cleaned.matchAll(/\/CFIDE\/adminapi\/customtags\/l10n\.cfm/gi)
    },
    {
        // See https://github.com/alt3kx/CVE-2022-1388_PoC
        name: 'Vulnerability/F5 BIG-IP/CVE-2022-1388 RCE',
        match: cleaned => cleaned.matchAll(/\/mgmt\/tm\/util\/bash/gi)
    },
    {
        // See https://securitynews.sonicwall.com/xmlpost/hackers-actively-targeting-remote-code-execution-vulnerability-on-zyxel-devices/
        name: 'Vulnerability/ZyXEL/CVE-2020-9054 RCE',
        match: cleaned => cleaned.matchAll(/\/adv,\/cgi-bin\/weblogin\.cgi/gi)
    },
    {
        // See https://vuldb.com/?id.165451
        name: 'Vulnerability/ZeroShell/v3.9.3/CVE-2020-29390 Command Injection',
        match: cleaned => cleaned.matchAll(/\/cgi-bin\/kerbynet\?[\w%_\.\-=&\\\/]*StartSessionSubmit/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/49096
        name: 'Vulnerability/ZeroShell/v3.9.0/CVE-2019-12725 Command Injection',
        match: cleaned => cleaned.matchAll(/\/cgi-bin\/kerbynet\?[\w%_\.\-=&\\\/]*Action=x509List/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/43984
        name: 'Vulnerability/Axis Camera RCE',
        match: cleaned => cleaned.matchAll(/\/incl\/image_test\.shtml/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/43982
        name: 'Vulnerability/GeoVision Camera/Auth Bypass',
        match: cleaned => cleaned.matchAll(/\/UserCreat\.cgi/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/43982
        name: 'Vulnerability/GeoVision Camera/RCE',
        match: cleaned => cleaned.matchAll(/\/(?:PictureCatch|JpegStream)\.cgi/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/43982
        name: 'Vulnerability/GeoVision Camera/Unauthorized Access',
        match: cleaned => cleaned.matchAll(/\/(?:geo-cgi\/sdk_config_set|geo-cgi\/sdk_fw_check|PSIA\/System\/)\.cgi/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/43982
        name: 'Vulnerability/GeoVision Camera/Double Free',
        match: cleaned => cleaned.matchAll(/\/PSIA\/System\/configurationData/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/43982
        name: 'Vulnerability/GeoVision Camera/Stack Overflow',
        match: cleaned => cleaned.matchAll(/\/(?:geo-cgi\/param|Login3gpp)\.cgi/gi)
    },
    {
        // See https://blog.katastros.com/a?ID=01800-20b4ee97-1675-4d3a-9baf-d2c6a0af4564
        name: 'Vulnerability/ThinkCMF/RCE',
        match: cleaned => cleaned.matchAll(/\/\?[\w%_\.\-=&\\\/]*(?:(?:a=fetch|templateFile=)[\w%_\.\-=&\\\/]*){2}/gi)
    },
    {
        // See https://github.com/mcw0/PoC/blob/master/TVT_and_OEM_IPC_NVR_DVR_RCE_Backdoor_and_Information_Disclosure.txt
        name: 'Vulnerability/TVT DVR/RCE',
        match: cleaned => cleaned.matchAll(/\/editBlackAndWhiteList/gi)
    },
    {
        name: 'Vulnerability/Log4j/v2.16.0/CVE-2021-44228 RCE (Log4Shell)',
        match: cleaned => cleaned.matchAll(/\$+\{jndi:[^\}#]+\}/gi), // # is excluded because that is an indicator of CVE-2021-45046
        decode: ([match]) => match.replaceAll(/Base64\/([A-Za-z0-9+\/=]+)/g, (pattern, base64) => {
            try {
                return Buffer.from(base64, 'base64').toString('utf-8');
            } catch {
                return pattern;
            }
        })
    },
    {
        // See https://www.lunasec.io/docs/blog/log4j-zero-day-severity-of-cve-2021-45046-increased/
        name: 'Vulnerability/Log4j/v2.17.0/CVE-2021-45046 RCE (Log4Shell 2)',
        match: cleaned => cleaned.matchAll(/\$+\{(?:ctx:[^\}]+|jndi:([^\}]+#[^\}]+))\}/gi),
        decode: ([match, rcePayload]) => {
            // CVE-2021-45046 allows RCE by inserting a #.
            // That is skipped by the above rule so we need to decode it here.
            if (rcePayload) {
                return match.replaceAll(/Base64\/([A-Za-z0-9+\/=]+)/g, (pattern, base64) => {
                    try {
                        return Buffer.from(base64, 'base64').toString('utf-8');
                    } catch {
                        return pattern;
                    }
                });
            }

            // Don't decode anything else (DoS / info leak payloads)
            return match
        }
    },
    {
        // Seehttps://www.exploit-db.com/exploits/50702
        name: 'Vulnerability/PHPUnit/v4.8.28/CVE-2017-9841 RCE',
        match: cleaned => cleaned.matchAll(/phpunit(\/\w+)*\/eval-stdin.php/gi)
    },
    {
        // See https://en.wikipedia.org/wiki/Shellshock_(software_bug)
        // See https://nvd.nist.gov/vuln/detail/cve-2014-6271
        name: 'Vulnerability/GNU Bash/v4.3/CVE-2014-6271 RCE (Shellshock)',
        match: cleaned => cleaned.matchAll(/(\s*)\s*\{\s*:\s*;\s*\}\s*;/g)
    },
    {
        // See https://www.cve.org/CVERecord?id=CVE-2014-7169
        name: 'Vulnerability/GNU Bash/v4.3 bash43-025/CVE-2014-7169 RCE (Shellshock 2)',
        match: cleaned => cleaned.matchAll(/(\s*)\s*\{\s*(\w+)\s*=\s*>\s*\\/g)
    },

    {
        // See https://blog.lumen.com/new-mozi-malware-family-quietly-amasses-iot-bots/
        name: 'Malware/Mozi',
        match: cleaned => cleaned.matchAll(/Mozi\.m/g)
    },
    {
        name: 'Malware/Webshell/Generic',
        match: cleaned => cleaned.matchAll(/\/(?:\?p4yl04d=|shell\?)[\w%\-\.&=\\\/]+/gi)
    },
    {
        name: 'Malware/Webshell/Sp3ctra',
        match: cleaned => cleaned.matchAll(/sp3ctra_XO\.php/gi)
    }
];

/** @type {Cleaner[]} */
const cleaners = [
    // Align slashes
    line => line.replaceAll(/\\/g, '/'),

    // Decode percent encoding
    line => line.replaceAll(/%([0-9A-Fa-f]{2})/g, ((match, hex) => {
        const asciiValue = parseInt(hex, 16);
        return String.fromCharCode(asciiValue);
    })),

    // Decode HTTP Basic auth header
    line => line.replaceAll(/\b(Basic\s+)([A-Za-z0-9+\/=]+)/gi), (match, prefix, b64) => {
        try {
            // Make sure to put the prefix back
            return prefix + Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    },

    // Decode Log4j expressions
    // 2022-06-10: Some of these allow symbols in the latter part
    line => line.replaceAll(/\$+\{\s*[\w:]*:-([^$}]+)\s*\}/g, (_, char) => char), // ${foo:-a}, ${::-a}, and ${foo:bar:-a} formats
    line => line.replaceAll(/\$+\{\s*(upper|lower):([^$}]+)\s*\}/gi, (_, operator, char) => { // ${lower:a} and ${upper:a} formats
        const op = operator.toLowerCase();
        if (op === 'lower') return char.toLowerCase();
        if (op === 'upper') return char.toUpperCase();
        return char;
    }),
    line => line.replaceAll(/\$+(upper|lower)\s*\{([^$}]+)\}\s*\}/gi, (_, operator, char) => { // $$lower{a} and $$upper{a} formats
        const op = operator.toLowerCase();
        if (op === 'lower') return char.toLowerCase();
        if (op === 'upper') return char.toUpperCase();
        return char;
    }),
    line => line.replaceAll(/\$+\{\s*base64:([A-Za-z0-9+\/=]+)\s*\}/gi, (match, b64) => { // ${base64:==} format
        try {
            return Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    }),
    line => line.replaceAll(/\/base64\/([A-Za-z0-9+\/=]+)/gi, (match, b64) => { // /Base64/abc format
        try {
            // Make sure to put the / back
            return '/' + Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    }),

    // Decode TVT ${IFS} inserts
    line => {
        // Try to limit to this one device
        if (/\/editBlackAndWhiteList/i.test(line)) {
            // Replace ${IFS} with a space
            return line.replaceAll(/\$\{\s*IFS\s*\}/gi, ' ');
        } else {
            return line;
        }
    },

    // Decode calls to md5sum. Current only handles echo piped to md5sum.
    line => line.replaceAll(/\b(echo(?:\s+[\-\w]+)*\s)([A-Za-z0-9+\/=]+)\s*\|\s*md5sum(?:\s+[\-\w]+)*/gi, (match, prefix, b64) => {
        try {
            return prefix + Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    })
];

/** @typedef {{key: string, keyRaw: string, value: string, raw: string, duplicate: CliArg | null}} CliArg */
/** @type {Record<string, CliArg>} */
const args = process.argv
    .slice(2)
    .map(arg => arg.match(/([^=]+)(?:=(.*))?/))
    .reduce((map, [argString, argKeyRaw, argValue]) => {
        const argKey = argKeyRaw.toLowerCase();
        map[argKey] = {
            key: argKey,
            keyRaw: argKeyRaw,
            value: argValue,
            raw: argString
        };
        return map;
    }, {});

function getFlagArg(arg) {
    return !!args[arg];
}
function getValueArg(arg, lower = false, def = null) {
    const argObj = args[arg];
    if (!argObj) {
        return def;
    }
    if (lower) {
        return argObj.value.toLowerCase()
    } else {
        return argObj.value;
    }
}
function getRepeatedArg(arg, lower = false, def = []) {
    const argObj = args[arg];
    if (!argObj) {
        return def;
    }

    const results = [];
    for (let curArg = argObj; curArg != null; curArg = curArg.duplicate) {
        let value = curArg.value;
        if (lower) {
            value = value.toLowerCase();
        }
        results.push(value);
    }
    return results;
}

if (getFlagArg('--help')) {
    console.log('Scans webserver log lines to detect suspicious behavior.')
    console.log('Logs should be piped through standard input, one line per log.');
    console.log('Findings will be printed to stdout, one line per finding.');
    console.log('All output is automatically sanitized to remove non-ascii-printable characters.');
    console.log();
    console.log('Depending on flags, output may contain the following components:');
    console.log('Finding:   Name of the rule that matched the output.');
    console.log('Index:     Index (line number) of the line that was matched. This is counted by lines received as piped input, not lines in the original file.');
    console.log('Match:     Portion of the line that was detected. This is automatically decoded / deobfuscated, if possible.');
    console.log('Line:      Entire content of the matched line. This is automatically decoded / deobfuscated, if possible.');
    console.log('Raw:       Same as "line", but NOT decoded. Only the standard sanitization is applied.');
    console.log();
    console.log('Standard output formats:');
    console.log('|TSV|Raw|Clean|Format                                           |Notes                               |');
    console.log('| X | X |  X  | [Finding]\\t[Index]\\t[Match]\\t[Line]\\t[Raw]      |                                    |');
    console.log('| X |   |  X  | [Finding]\\t[Index]\\t[Match]\\t[Line]             |                                    |');
    console.log('|   | X |  X  | [Finding]: [Index] {[Match]} {[Line]} {[Raw]}   |Index is left-padded to 9 characters|');
    console.log('|   |   |  X  | [Finding]: [Index] {[Match]} {[Line]}           |Index is left-padded to 9 characters|');
    console.log('| X | X |     | [Finding]\\t[Index]\\t[Match]\\t[Raw]              |                                    |');
    console.log('| X |   |     | [Finding]\\t[Index]\\t[Match]                     |                                    |');
    console.log('|   | X |     | [Finding]: [Index] {[Match]} {[Raw]}            |Index is left-padded to 9 characters|');
    console.log('|   |   |     | [Finding]: [Index] {[Match]}                    |Index is left-padded to 9 characters|');
    console.log();
    console.log('Usage: find-suspicious-logs [options]');
    console.log('--help                 Print help and exit.');
    console.log('--version              Print version and exit.');
    console.log('--tsv                  Output in TSV (tab-delimited) format.');
    console.log('--cleaned=<Y/N>        Include the entire cleaned, decoded line in the output. Defaults to Y (on).')
    console.log('--raw=<Y/N>            Include the entire raw, undecoded line in the output. Defaults to N (off)');
    console.log('--include=<patterns>   Patterns to include rules (comma separated). Only matching rules will be run.');
    console.log('--exclude=<patterns>   Patterns to exclude rules (comma separated). Overrides --include option..');
    console.log('--list-rules           List all rules and exit.')

    // Stop executing after processing help.
    process.exit(0);
}

if (getFlagArg('--version')) {
    console.log('find-suspicious-logs version 1.4.0 (2022-06-12)');
    process.exit(0);
}


if (getFlagArg('--list-rules')) {
    // Sort rules alphabetically
    const sortedRules = Array.from(allRules)
        .sort((a, b) => a.name.localeCompare(b.name));

    // Print all rules
    for (const rule of sortedRules) {
        console.log(rule.name);
    }

    // Stop executing after printing rules.
    process.exit(0);
}

// Parse flags
const isTsv = getFlagArg('--tsv');
const includeVerbose = getValueArg('--raw', true, 'n') === 'y';
const includeCleaned = getValueArg('--cleaned', true, 'y') === 'y';

// Select rules
const includes = getRepeatedArg('--include', false, []).flatMap(include => include.split(','));
const excludes = getRepeatedArg('--exclude', false, []).flatMap(exclude => exclude.split(','));
const rules = allRules.filter(rule => {
    // If includes are specified, AND none of them match, then exclude this rule.
    if (includes.length > 0 && !includes.some(include => rule.name.includes(include))) {
        return false;
    }

    // If any exclude matches, then exclude this rule
    if (excludes.some(exclude => rule.name.includes(exclude))) {
        return false;
    }

    return true;
});

/**
 * @param {TemplateStringsArray} strings
 * @param  {...unknown} values
 * @returns {string}
 */
function sanitize(strings, ...values) {
    const parts = [ strings[0] ];
    for (let i = 0; i < values.length; i++) {
        const value = sanitizers.reduce((val, san) => san(val), String(values[i]));
        parts.push(value);
        parts.push(strings[i + 1]);
    }
    return parts.join('');
}

/**
 * @param {Rule} rule
 * @param {string} match
 * @param {string} cleaned
 * @param {string} raw
 * @param {number} lineNumber
 */
function writeMatch(rule, match, cleaned, raw, lineNumber) {
    const log = getMatchString(rule, match, cleaned, raw, lineNumber);
    console.log(log);
}

/**
 * @param {Rule} rule
 * @param {string} match
 * @param {string} cleaned
 * @param {string} raw
 * @param {number} lineNumber
 * @returns {string}
 */
function getMatchString(rule, match, cleaned, raw, lineNumber) {
    if (isTsv) {
        if (includeCleaned) {
            if (includeVerbose) {
                return sanitize`${rule.name}\t${lineNumber}\t${match}\t${cleaned}\t${raw}`;
            } else {
                return sanitize`${rule.name}\t${lineNumber}\t${match}\t${cleaned}`;
            }
        } else {
            if (includeVerbose) {
                return sanitize`${rule.name}\t${lineNumber}\t${match}\t${raw}`;
            } else {
                return sanitize`${rule.name}\t${lineNumber}\t${match}`;
            }
        }
    } else {
        if (includeCleaned) {
            if (includeVerbose) {
                return sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}} {${cleaned}} {${raw}}`;
            } else {
                return sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}} {${cleaned}}`;
            }
        } else {
            if (includeVerbose) {
                return sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}} {${raw}}`;
            } else {
                return sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}}`;
            }
        }
    }
}

/**
 * @param {string} line
 * @returns {string}
 */
function cleanLine(line) {
    while (true) {
        const newLine = cleaners.reduce((l, cleaner) => cleaner(l), line);
        if (newLine === line) {
            break;
        }
        line = newLine;
    }
    return line;
}

/**
 * @param {string} raw
 * @param {number} lineNumber
 */
function processLine(raw, lineNumber) {
    // Run all cleaners
    const cleaned = cleanLine(raw);

    // Run all rules
    for (const rule of rules) {
        // Apply the rule
        const matches = rule.match(cleaned, raw);

        // Decode and print all matches
        for (const match of matches) {
            // Decode the line, or fall back to the raw match
            const decoded = rule.decode ? rule.decode(match, cleaned, raw) : match[0];

            // Write output
            writeMatch(rule, decoded, cleaned, raw, lineNumber);
        }
    }
}

// Count the lines
let lineNumber = 0;

// Read STDIN until close
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', line => {
    // Process each incoming line
    processLine(line, lineNumber);

    lineNumber++;
});