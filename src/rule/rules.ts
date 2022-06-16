/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Rule} from "./rule.js";

/**
 * All defined scan rules
 */
export const allRules: readonly Rule[] = [
    {
        name: 'Payload/Script/PHP',
        description: 'Detects PHP source code by matching <?php and <?= tags.',
        match: cleaned => cleaned.matchAll(/<(?:\??php\b|\?=)/gi)
    },
    {
        name: 'Payload/Script/Shebang',
        description: 'Detects *nix scripts by matching the shebang (#!) directive.',
        match: cleaned => cleaned.matchAll(/#!\/?(?:[\w.\-]+\/)*\w+\s/gi)
    },
    {
        name: 'Payload/Shell/Linux',
        description: 'Detects *nix scripts by matching common shell commands.',
        match: cleaned => cleaned.matchAll(/\b(?:chmod|bash|sudo|echo|cat)(?=[\s<>|&])/gi)
    },
    {
        name: 'Payload/Shell/Windows',
        description: 'Detects Windows scripts by matching common script runtimes and batch commands.',
        match: cleaned => cleaned.matchAll(/\b(?:powershell|cmd|echo|jscript|cscript)(?=[\s<>|&])/gi)
    },
    {
        name: 'Payload/generic/Eval',
        description: 'Detects "eval" style functions. These are often used in shellcode to pivot to a stronger payload.',
        match: cleaned => cleaned.matchAll(/\b(?:exec|eval)(?=[\s(])/gi)
    },
    {
        name: 'Payload/Executable/generic',
        description: 'Detects file extensions of common cross-platform executable formats. This rule tends to generate a lot of noise.',
        match: cleaned => cleaned.matchAll(/\.(?:py|class|jar|war|ear|rb)\b/gi)
    },
    {
        name: 'Payload/Executable/Windows',
        description: 'Detects file extensions of common Windows-specific executable formats.',
        match: cleaned => cleaned.matchAll(/\.(?:bat|cmd|ps[12]|vbs|vba|lnk)\b/gi)
    },
    {
        name: 'Payload/Executable/Linux',
        description: 'Detects file extensions of common Linux-specific executable formats. This rule tends to generate a lot of noise due to embedded web servers that expose APIs via shell scripts.',
        match: cleaned => cleaned.matchAll(/\.sh\b/gi)
    },
    {
        name: 'Payload/Downloader/generic',
        description: 'Detects functions and utilities that are commonly used to download additional payloads.',
        match: cleaned => cleaned.matchAll(/\b(?:wget|curl|nc|Net\.WebClient|Invoke-WebRequest|bitsadmin)\b/gi)
    },
    {
        name: 'Payload/Downloader/netcat',
        description: 'Detects calls to netcat, which is commonly used to download payloads on embedded linux systems. This rule will attempt to capture all arguments including the target URL to assist further analysis.',
        match: cleaned => cleaned.matchAll(/\bnc(?:\s*-\w\s?[\w:-]*)*\s+\w+(?:\.\w+)*\s+\d+-?\d*/gi)
    },
    {
        name: 'Payload/Downloader/wget',
        description: 'Detects calls to wget, which is commonly used to download payloads on Linux servers. This rule will attempt to capture all arguments including the target URL to assist further analysis.',
        match: cleaned => cleaned.matchAll(/\bwget(?:\s+-\w\s?[\w:\/\\.\-_%]*|\s+--[\w_\-]+=[\w:\/\\.\-_%]+)*\s+[\w:\/\\.\-_%]+/gi)
    },
    {
        name: 'Payload/Downloader/curl',
        description: 'Detects calls to curl, which is commonly used to download payloads on Linux servers. This rule will attempt to capture all arguments including the target URL to assist further analysis.',
        match: cleaned => cleaned.matchAll(/\bcurl(?:\s+-{1,2}[\w\-]+\s?[\w:\/\\.\-_%]*)*\s+[\w:\/\\.\-_%]+/gi)
    },

    {
        name: 'Obfuscation/Interpolation',
        description: 'Detects interpolated strings, which are commonly used to obfuscate shellcode. Interpolation is also commonly used to leak sensitive information. This rule generates a LOT of noise when scanning attempts to exploit Log4Shell.',
        match: cleaned => cleaned.matchAll(/\$+\{[\w:-]*\w+[\w:-]*}/g)
    },

    {
        // Expanded list from https://stackoverflow.com/a/4669755
        // 2022-06-10: URLs can contain []
        name: 'Vulnerability/generic/traversal',
        description: 'Insecure web servers will allow access to private files by inserting ../ into the URL.',
        match: cleaned => cleaned.matchAll(/[A-Za-z\d\-._~!$&'()*+,;=:@\/?\[\]]*\/\.\.\/[A-Za-z\d\-._~!$&'()*+,;=:@\/?\[\]]*/g)
    },
    {
        name: 'Vulnerability/CKEditor/v4.4.7/RCE',
        description: '(F)CKEditor 4.4.7 and older is vulnerable to XSS and RCE via various pages.',
        links: [ 'https://packetstormsecurity.com/files/130807/Ckeditor-4.4.7-Shell-Upload-Cross-Site-Scripting.html' ],
        match: cleaned => cleaned.matchAll(/\bf?ckeditor[\/\\](?:editor|_?samples)[\/\\](?:plugins|php|filemanager)/gi)
    },
    {
        name: 'Vulnerability/HiSilicon DVR/RCE',
        description: 'Many models of HiSilicon-based DVR devices are vulnerable to RCE via /mnt/mtd/Config/Account1.',
        links: [ 'https://github.com/tothi/pwn-hisilicon-dvr/blob/master/README.adoc' ],
        match: cleaned => cleaned.matchAll(/\/mnt\/mtd\/Config\/Account1/gi)
    },
    {
        name: 'Vulnerability/FortiOS/CVE-2018-13379 Path Traversal',
        description: 'Multiple version of FortiOS are vulnerable to path traversal that allows arbitrary file disclosure via /remote/fgt_lang/.',
        links: [
            'https://gist.github.com/code-machina/bae5555a771062f2a8225fd4731ae3f7',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-13379'
        ],
        match: cleaned => cleaned.matchAll(/\/remote\/fgt_lang\?/gi)
    },
    {
        name: 'Vulnerability/PHPCMS/Auth Bypass',
        description: 'Some versions of PHPCMS are vulnerable to admin-level auth bypass via cachefile parameter on api.php.',
        links: [ 'https://blog.karatos.in/a?ID=01350-dad9c8fa-17e5-403c-9d7c-d26d82e59ec9' ],
        match: cleaned => cleaned.matchAll(/\/api\.php\?[\w%_.\-=&\\\/]*cachefile=[\w%_.\-=&\\\/]*/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/appointment-booking-calendar/v1.1.24/SQLi',
        description: 'Wordpress plugin appointment-booking-calendar version 1.1.24 and older are vulnerable to SQLi via cpabc_appointments_calendar_update action on admin-ajax.php.',
        links: [ 'https://www.exploit-db.com/exploits/39342' ],
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin-ajax\.php\?[\w%_.\-=&\\\/]*action=cpabc_appointments_calendar_update[\w%_.\-=&\\\/]*/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/multi-meta-box/v1.0/SQLi',
        description: 'Wordpress plugin multi-meta-box version 1.0 and older are vulnerable to SQL via admin.php.',
        links: [
            'https://packetstormsecurity.com/files/136627/WordPress-Multiple-Meta-Box-1.0-SQL-Injection.html',
            'https://gist.github.com/nikcub/9a4d68827e3770587287c254cbf7361a'
        ],
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin\.php\?[\w%_.\-=&\\\/]*page=multi_metabox_listing[\w%_.\-=&\\\/]*/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/aspose-doc-exporter/v1.0/Arbitrary File Download',
        description: 'Wordpress plugin aspose-doc-exporter version 1.0 and older are vulnerable to arbitrary file disclosure via aspose_doc_exporter_download.php.',
        links: [ 'https://www.exploit-db.com/exploits/36559' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/aspose-doc-exporter\/aspose_doc_exporter_download\.php/gi)
        // To capture more, add \?[\w%_\.\-=&\\\/]*file=[\w%_\.\-=&\\\/]*
    },
    {
        name: 'Vulnerability/Wordpress/plugin/db-backup/v4.5/CVE-2014-9119 Arbitrary File Disclosure',
        description: 'Wordpress plugin db-backup version 4.5 and older are vulnerable to arbitrary file disclosure via download.php.',
        links: [
            'https://www.exploit-db.com/exploits/35378',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9119'
        ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/db-backup\/download\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/google-document-embedder/v2.4.6/Arbitrary File Disclosure',
        description: 'Wordpress plugin google-document-embedder version 2.4.6 and older are vulnerable to arbitrary file disclosure via libs/pdf.php.',
        links: [ 'https://www.exploit-db.com/exploits/23970' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/google-document-embedder\/libs\/pdf\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/google-document-embedder/v2.5.14/SQLi',
        description: 'Wordpress plugin google-document-embedder version 2.5.14 and older are vulnerable to SQLi via view.php.',
        links: [ 'https://www.exploit-db.com/exploits/35371' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/google-document-embedder\/view\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/cherry-plugin/v1.2.6/Arbitrary File Disclosure',
        description: 'Wordpress plugin cherry-plugin version 1.2.6 and older are vulnerable to arbitrary file disclosure via admin/import-export/download-content.php.',
        links: [ 'https://wpscan.com/vulnerability/90034817-dee7-40c9-80a2-1f1cd1d033ee' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/cherry-plugin\/admin\/import-export\/download-content\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/google-mp3-audio-player/v1.0.11/Arbitrary File Disclosure',
        description: 'Wordpress plugin google-mp3-audio-player version 1.0.11 and older are vulnerable to arbitrary file disclosure va direct_download.php.',
        links: [ 'https://www.exploit-db.com/exploits/35460' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/google-mp3-audio-player\/direct_download\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/mac-dock-gallery/v2.9/Arbitrary File Disclosure',
        description: 'Wordpress plugin mac-doc-gallery version 2.9 and older are vulnerable to arbitrary file disclosure via macdownload.php.',
        links: [ 'https://www.tenable.com/plugins/nessus/62205' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mac-dock-gallery\/macdownload\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/mac-dock-gallery/v2.7/Arbitrary File Upload',
        description: 'Wordpress plugin mac-dock-gallery version 2.7 and older are vulnerable to arbitrary file upload via upload-file.php.',
        links: [ 'https://www.exploit-db.com/exploits/19056' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mac-dock-gallery\/upload-file\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/mini-mail-dashboard-widget/v1.36/Remote File Inclusion',
        description: 'Wordpress plugin mini-mail-dashboard-widget version 1.36 and older are vulnerable to RCE via RFI on mini-mail-dashboard-widgetwp-mini-mail.php.',
        links: [ 'https://www.exploit-db.com/exploits/17868' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mini-mail-dashboard-widgetwp-mini-mail\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/mygallery/v1.4b4/CVE-2007-2426 Remote File Inclusion',
        description: 'Wordpress plugin mygallery version 1.4b4 and older are vulnerable to RCE via RFI on myfunctions/mygallerybrowser.php.',
        links: [ 'https://www.exploit-db.com/exploits/3814' ],
        cve: 'CVE-2007-2426',
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/mygallery\/myfunctions\/mygallerybrowser\.php/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/recent-backups/v0.7/Arbitrary File Disclosure',
        description: 'Wordpress plugin recent-backups version 0.7 and older are vulnerable to arbitrary file disclosure via download-file.php.',
        links: [ 'https://www.exploit-db.com/exploits/37752' ],
        match: cleaned => cleaned.matchAll(/\/wp-content\/plugins\/recent-backups\/download-file\.php/gi)
    },
    {
        name: 'Vulnerability/ColdFusion/v10/Credential Disclosure',
        description: 'ColdFusion 8, 9, and 10 are vulnerable to auth bypass via credential disclosure on /CFIDE/adminapi/customtags/l10n.cfm.',
        links: [ 'https://www.exploit-db.com/exploits/25305' ],
        match: cleaned => cleaned.matchAll(/\/CFIDE\/adminapi\/customtags\/l10n\.cfm/gi)
    },
    {
        name: 'Vulnerability/F5 BIG-IP/CVE-2022-1388 RCE',
        description: 'Some F5 BIG-IP devices are vulnerable to RCE via /mgmt/tm/util/bash.',
        links: [ 'https://github.com/alt3kx/CVE-2022-1388_PoC' ],
        cve: 'CVE-2022-1388',
        match: cleaned => cleaned.matchAll(/\/mgmt\/tm\/util\/bash/gi)
    },
    {
        name: 'Vulnerability/ZyXEL/CVE-2020-9054 RCE',
        description: 'Some ZyXEL devices are vulnerable to RCE via /adv,/cgi-bin/weblogin.cgi.',
        links: [ 'https://securitynews.sonicwall.com/xmlpost/hackers-actively-targeting-remote-code-execution-vulnerability-on-zyxel-devices/' ],
        cve: 'CVE-2020-9054',
        match: cleaned => cleaned.matchAll(/\/adv,\/cgi-bin\/weblogin\.cgi/gi)
    },
    {
        name: 'Vulnerability/ZeroShell/v3.9.3/CVE-2020-29390 Command Injection',
        description: 'ZeroShell Linux version 3.9.3 is vulnerable to RCE via command injection in the StartSessionSubmit parameter on /cgi-bin/kerbynet.',
        links: [ 'https://vuldb.com/?id.165451' ],
        cve: 'CVE-2020-29390',
        match: cleaned => cleaned.matchAll(/\/cgi-bin\/kerbynet\?[\w%_.\-=&\\\/]*StartSessionSubmit/gi)
    },
    {
        name: 'Vulnerability/ZeroShell/v3.9.0/CVE-2019-12725 Command Injection',
        description: 'ZeroShell Linux version 3.9.0 is vulnerable to RCE via command injection in /cgi-bin/kerbynet.',
        links: [ 'https://www.exploit-db.com/exploits/49096' ],
        cve: 'CVE-2019-12725',
        match: cleaned => cleaned.matchAll(/\/cgi-bin\/kerbynet\?[\w%_.\-=&\\\/]*Action=x509List/gi)
    },
    {
        name: 'Vulnerability/Axis Camera RCE',
        description: 'Many models of Axis IP Cameras are vulnerable to RCE via command injection in /incl/image_test.shtml. The camnbr parameter is not properly escaped and allows shell commands to be injected.',
        links: [ 'https://www.exploit-db.com/exploits/43984' ],
        match: cleaned => cleaned.matchAll(/\/incl\/image_test\.shtml/gi)
    },
    {
        name: 'Vulnerability/GeoVision Camera/Auth Bypass',
        description: 'Many models of GeoVision IP Cameras are vulnerable to authentication bypass. A new admin account can be created without authorization due to missing security on /UserCreat.cgi.',
        links: [ 'https://www.exploit-db.com/exploits/43982' ],
        match: cleaned => cleaned.matchAll(/\/UserCreat\.cgi/gi)
    },
    {
        name: 'Vulnerability/GeoVision Camera/RCE',
        description: 'Many models of GeoVision IP Cameras are vulnerable to RCE via command injection on /PictureCatch.cgi and /JpegStream.cgi. The password parameter is not properly escaped and allows shell commands to be injected.',
        links: [ 'https://www.exploit-db.com/exploits/43982' ],
        match: cleaned => cleaned.matchAll(/\/(?:PictureCatch|JpegStream)\.cgi/gi)
    },
    {
        name: 'Vulnerability/GeoVision Camera/Unauthorized Access',
        description: 'Many models of GeoVision IP Cameras are vulnerable to unauthorized access. This can be attained in numerous ways through /geo-cgi/sdk_config_set.cgi, /geo-cgi/sdk_fw_check.cgi, and /PSIA/System.cgi.',
        links: [ 'https://www.exploit-db.com/exploits/43982' ],
        match: cleaned => cleaned.matchAll(/\/(?:geo-cgi\/sdk_config_set|geo-cgi\/sdk_fw_check|PSIA\/System\/)\.cgi/gi)
    },
    {
        name: 'Vulnerability/GeoVision Camera/Double Free',
        description: 'Many models of GeoVision IP Cameras are vulnerable to RCE via double-free exploit in /PSIA/System/configurationData. Memory can be corrupted to execute arbitrary code.',
        links: [ 'https://www.exploit-db.com/exploits/43982' ],
        match: cleaned => cleaned.matchAll(/\/PSIA\/System\/configurationData/gi)
    },
    {
        name: 'Vulnerability/GeoVision Camera/Stack Overflow',
        description: 'Many models of GeoVision IP Cameras are vulnerable to RCE via stack overflow exploits in /geo-cgi/param.cgi and /Login3gpp.cgi. Memory can be corrupted to execute arbitrary code.',
        links: [ 'https://www.exploit-db.com/exploits/43982' ],
        match: cleaned => cleaned.matchAll(/\/(?:geo-cgi\/param|Login3gpp)\.cgi/gi)
    },
    {
        name: 'Vulnerability/ThinkCMF/RCE',
        description: 'Some versions of ThinkCMF are vulnerable to RCE via RFI through the templateFile parameter. ThinkCMF can be directed to load an attacker-controlled file as a template, which allows code execution.',
        links: [ 'https://blog.katastros.com/a?ID=01800-20b4ee97-1675-4d3a-9baf-d2c6a0af4564' ],
        match: cleaned => cleaned.matchAll(/\/\?[\w%_.\-=&\\\/]*(?:(?:a=fetch|templateFile=)[\w%_.\-=&\\\/]*){2}/gi)
    },
    {
        name: 'Vulnerability/TVT DVR/RCE',
        description: 'Some models of TVT DVRs are vulnerable to RCE via /editBlackAndWhiteList. The content of the <IP></IP> element are not escaped and can contain shell commands. Spaces are not allowed, but ${IFS} can be used to insert one.',
        links: [ 'https://github.com/mcw0/PoC/blob/master/TVT_and_OEM_IPC_NVR_DVR_RCE_Backdoor_and_Information_Disclosure.txt' ],
        match: cleaned => cleaned.matchAll(/\/editBlackAndWhiteList/gi)
    },
    {
        name: 'Vulnerability/Log4j/v2.16.0/CVE-2021-44228 RCE (Log4Shell)',
        description: 'Log4j version 2.16.0 and older are vulnerable to RCE. By default, Log4j evaluates inline templates from untrusted strings. Templates are permitted to access remote resources via JNDI, which can operate over the internet using LDAP. Additionally, JNDI allows the remote LDAP server to provide a Java class file that will be downloaded and executed. This is an extremely "easy" exploit and saw widespread use after being released as a zero-day in late 2019.',
        cve: 'CVE-2021-44228',
        match: cleaned => cleaned.matchAll(/\$+\{jndi:[^}#]+}/gi), // \# is excluded because that is an indicator of CVE-2021-45046
        decode: ([match]) => match.replaceAll(/Base64\/([A-Za-z\d+\/=]+)/g, (pattern, base64) => {
            try {
                return Buffer.from(base64, 'base64').toString('utf-8');
            } catch {
                return pattern;
            }
        })
    },
    {
        name: 'Vulnerability/Log4j/v2.17.0/CVE-2021-45046 RCE (Log4Shell 2)',
        description: 'Log4j version 2.17.0 and older are vulnerable to RCE caused by an incomplete fix for CVE-2021-44338. By inserting a #, the fix can be entirely bypassed.',
        links: [ 'https://www.lunasec.io/docs/blog/log4j-zero-day-severity-of-cve-2021-45046-increased/' ],
        cve: 'CVE-2021-45046',
        match: cleaned => cleaned.matchAll(/\$+\{(?:ctx:[^}]+|jndi:([^}]+#[^}]+))}/gi),
        decode: ([match, rcePayload]) => {
            // CVE-2021-45046 allows RCE by inserting a #.
            // That is skipped by the above rule so we need to decode it here.
            if (rcePayload) {
                return match.replaceAll(/Base64\/([A-Za-z\d+\/=]+)/g, (pattern, base64) => {
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
        name: 'Vulnerability/PHPUnit/v4.8.28/CVE-2017-9841 RCE',
        description: 'PHPUnit version 4.8.28 and older are vulnerable to RCE via eval-stdin.php. This file executes any input as PHP code.',
        links: [ 'https://www.exploit-db.com/exploits/50702' ],
        cve: 'CVE-2017-9841',
        match: cleaned => cleaned.matchAll(/phpunit(\/\w+)*\/eval-stdin.php/gi)
    },
    {
        name: 'Vulnerability/GNU Bash/v4.3/CVE-2014-6271 RCE (Shellshock)',
        description: 'GNU Bash version 4.3 and older are vulnerable to RCE by inserting a specific combination of special characters. The Bash parser becomes confused and incorrectly executes attacker-controlled variable contents as script.',
        links: [
            'https://en.wikipedia.org/wiki/Shellshock_(software_bug)',
            'https://nvd.nist.gov/vuln/detail/cve-2014-6271'
        ],
        cve: 'CVE-2014-6271',
        match: cleaned => cleaned.matchAll(/(\s*)\s*\{\s*:\s*;\s*}\s*;/g)
    },
    {
        name: 'Vulnerability/GNU Bash/v4.3 bash43-025/CVE-2014-7169 RCE (Shellshock 2)',
        description: 'GNU Bash versions between 4.3 and 4.3 bash43-025 are vulnerable to RCE due to an incomplete fix for CVE-2014-6271.',
        links: [ 'https://www.cve.org/CVERecord?id=CVE-2014-7169' ],
        cve: 'CVE-2014-7169',
        match: cleaned => cleaned.matchAll(/(\s*)\s*\{\s*(\w+)\s*=\s*>\s*\\/g)
    },

    {
        name: 'Malware/Mozi',
        description: 'The Mozi botnet targets embedded IoT (Internet of Things) devices using known but frequently unpatched vulnerabilities. This rule attempts to detect it by recognizing its most common filenames.',
        links: [ 'https://blog.lumen.com/new-mozi-malware-family-quietly-amasses-iot-bots/' ],
        match: cleaned => cleaned.matchAll(/\bMozi\.m\b/gi)
    },
    {
        name: 'Malware/Webshell/generic',
        description: 'This rule matches URLs that are commonly used to access webshells.',
        match: cleaned => cleaned.matchAll(/\/(?:\?p4yl04d=|shell\?)[\w%\-.&=\\\/]+/gi)
    },
    {
        name: 'Malware/Webshell/Sp3ctra',
        description: 'This rule detects the Sp3ctra webshell using its most common filename.',
        match: cleaned => cleaned.matchAll(/sp3ctra_XO\.php/gi)
    }
];