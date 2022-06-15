/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Rule} from "./rule.js";

/**
 * All defined scan rules
 */
export const allRules: readonly Rule[] = [
    {
        name: 'Payload/Script/PHP',
        match: cleaned => cleaned.matchAll(/<(?:\??php\b|\?=)/gi)
    },
    {
        name: 'Payload/Script/Shebang',
        match: cleaned => cleaned.matchAll(/#!\/?(?:[\w.\-]+\/)*\w+\s/gi)
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
        name: 'Payload/Executable/generic',
        match: cleaned => cleaned.matchAll(/\.(?:py|class|jar|war|ear|rb)\b/gi)
    },
    {
        name: 'Payload/Executable/Windows',
        match: cleaned => cleaned.matchAll(/\.(?:bat|cmd|ps[12]|vbs|vba|lnk)\b/gi)
    },
    {
        name: 'Payload/Executable/Linux',
        match: cleaned => cleaned.matchAll(/\.sh\b/gi)
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
        match: cleaned => cleaned.matchAll(/\bwget(?:\s+-\w\s?[\w:\/\\.\-_%]*|\s+--[\w_\-]+=[\w:\/\\.\-_%]+)*\s+[\w:\/\\.\-_%]+/gi)
    },
    {
        name: 'Payload/Downloader/curl',
        match: cleaned => cleaned.matchAll(/\bcurl(?:\s+-{1,2}[\w\-]+\s?[\w:\/\\.\-_%]*)*\s+[\w:\/\\.\-_%]+/gi)
    },

    {
        name: 'Obfuscation/Interpolation',
        match: cleaned => cleaned.matchAll(/\$+\{[\w:-]*\w+[\w:-]*}/g)
    },

    {
        // Expanded list from https://stackoverflow.com/a/4669755
        // 2022-06-10: URLs can contain []
        name: 'Vulnerability/generic/traversal',
        match: cleaned => cleaned.matchAll(/[A-Za-z\d\-._~!$&'()*+,;=:@\/?\[\]]*\/\.\.\/[A-Za-z\d\-._~!$&'()*+,;=:@\/?\[\]]*/g)
    },
    {
        // See https://packetstormsecurity.com/files/130807/Ckeditor-4.4.7-Shell-Upload-Cross-Site-Scripting.html
        name: 'Vulnerability/CKEditor/v4.4.7/RCE',
        match: cleaned => cleaned.matchAll(/\bf?ckeditor[\/\\](?:editor|_?samples)[\/\\](?:plugins|php|filemanager)/gi)
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
        match: cleaned => cleaned.matchAll(/\/api\.php\?[\w%_.\-=&\\\/]*cachefile=[\w%_.\-=&\\\/]*/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/39342
        name: 'Vulnerability/Wordpress/plugin/appointment-booking-calendar/v1.1.24/SQLi',
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin-ajax\.php\?[\w%_.\-=&\\\/]*action=cpabc_appointments_calendar_update[\w%_.\-=&\\\/]*/gi)
    },
    {
        // See https://packetstormsecurity.com/files/136627/WordPress-Multiple-Meta-Box-1.0-SQL-Injection.html
        // See https://gist.github.com/nikcub/9a4d68827e3770587287c254cbf7361a
        name: 'Vulnerability/Wordpress/plugin/multi-meta-box/v1.0/SQLi',
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin\.php\?[\w%_.\-=&\\\/]*page=multi_metabox_listing[\w%_.\-=&\\\/]*/gi)
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
        name: 'Vulnerability/Wordpress/plugin/db-backup/v4.5/CVE-2014-9119 Arbitrary File Disclosure',
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
        match: cleaned => cleaned.matchAll(/\/cgi-bin\/kerbynet\?[\w%_.\-=&\\\/]*StartSessionSubmit/gi)
    },
    {
        // See https://www.exploit-db.com/exploits/49096
        name: 'Vulnerability/ZeroShell/v3.9.0/CVE-2019-12725 Command Injection',
        match: cleaned => cleaned.matchAll(/\/cgi-bin\/kerbynet\?[\w%_.\-=&\\\/]*Action=x509List/gi)
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
        match: cleaned => cleaned.matchAll(/\/\?[\w%_.\-=&\\\/]*(?:(?:a=fetch|templateFile=)[\w%_.\-=&\\\/]*){2}/gi)
    },
    {
        // See https://github.com/mcw0/PoC/blob/master/TVT_and_OEM_IPC_NVR_DVR_RCE_Backdoor_and_Information_Disclosure.txt
        name: 'Vulnerability/TVT DVR/RCE',
        match: cleaned => cleaned.matchAll(/\/editBlackAndWhiteList/gi)
    },
    {
        name: 'Vulnerability/Log4j/v2.16.0/CVE-2021-44228 RCE (Log4Shell)',
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
        // See https://www.lunasec.io/docs/blog/log4j-zero-day-severity-of-cve-2021-45046-increased/
        name: 'Vulnerability/Log4j/v2.17.0/CVE-2021-45046 RCE (Log4Shell 2)',
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
        // Seehttps://www.exploit-db.com/exploits/50702
        name: 'Vulnerability/PHPUnit/v4.8.28/CVE-2017-9841 RCE',
        match: cleaned => cleaned.matchAll(/phpunit(\/\w+)*\/eval-stdin.php/gi)
    },
    {
        // See https://en.wikipedia.org/wiki/Shellshock_(software_bug)
        // See https://nvd.nist.gov/vuln/detail/cve-2014-6271
        name: 'Vulnerability/GNU Bash/v4.3/CVE-2014-6271 RCE (Shellshock)',
        match: cleaned => cleaned.matchAll(/(\s*)\s*\{\s*:\s*;\s*}\s*;/g)
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
        name: 'Malware/Webshell/generic',
        match: cleaned => cleaned.matchAll(/\/(?:\?p4yl04d=|shell\?)[\w%\-.&=\\\/]+/gi)
    },
    {
        name: 'Malware/Webshell/Sp3ctra',
        match: cleaned => cleaned.matchAll(/sp3ctra_XO\.php/gi)
    }
];