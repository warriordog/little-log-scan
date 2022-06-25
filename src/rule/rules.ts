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
        match: cleaned => cleaned.matchAll(/\b(?:chmod|bash|sudo|echo|cat)\b/gi)
    },
    {
        name: 'Payload/Shell/Windows',
        description: 'Detects Windows scripts by matching common script runtimes and batch commands.',
        match: cleaned => cleaned.matchAll(/\b(?:powershell|cmd|echo|jscript|cscript|csi|dnx|rcsi)(?=\s)/gi)
    },
    {
        name: 'Payload/Execute/Functions/generic',
        description: 'Detects script functions that are used to execute other code. These are often used in shellcode to pivot to a stronger payload.',
        match: cleaned => cleaned.matchAll(/\b(?:exec|eval|Net\.WebClient|Invoke-WebRequest)\b/gi)
    },
    {
        name: 'Payload/Execute/Tools/generic/Windows',
        description: 'Detects tools, applications, and functions that are used to execute other code. These are often used in shellcode to pivot to a stronger payload.',
        match: cleaned => cleaned.matchAll(/\b(?:Atbroker|cmstp|Diskshadow|Dnscmd|Explorer|Extexport|Forfiles|Ie4uinit|Infdefaultinstall|Installutil|Mavinject|Microsoft\.Workflow\.Compiler|Msbuild|Msdt|Mshta|Msiexec|Netsh|Odbcconf|Pcalua|Pcwrun|Pnputil|Presentationhost|Rasautou|Regasm|Register-cimprovider|Regsvcs|Regsvr32|Rundll32|Runonce|Runscripthelper|Schtasks|Scriptrunner|SettingSyncHost|Stordiag|SyncAppvPublishingServer|Ttdinject|Tttracer|Verclsid|Wlrmdr|Wmic|WorkFolders|wuauclt|AccCheckConsole|AgentExecutor|Appvlp|Bginfo|coregen|DefaultPack|Devtoolslauncher|Dotnet|Dxcap|Mftrace|Msdeploy|msxsl|Procdump|Procdump64|Remote|Sqlps|SQLToolsPS|Tracker|VSIISExeLauncher|vsjitdebugger|Ieexec|Xwizard)(?=\s)|\bDesk\.cpl\b|\b(?:Advpack|Ieadvpack|Ieframe|Mshtml|Pcwutl|Setupapi|Shdocvw|Shell32|Syssetup)\.dll\b/gi)    },
    {
        name: 'Payload/Execute/Tools/bitsadmin',
        description: 'Detects usage of the bitsadmin tool to execute other code. This can be used to pivot to stronger payload.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes the /SetNotifyCmdLine switch (used for execution)
            for (const match of cleaned.matchAll(/\bbitsadmin\s[\s\w\/\\.:\-]+/gi)) {
                if (match[0].toLowerCase().includes('/setnotifycmdline')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Execute/Tools/certoc',
        description: 'Detects usage of the CertOC tool to execute other code. This can be used to pivot to stronger payload.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes the -LoadDLL switch (used for execution)
            for (const match of cleaned.matchAll(/\bcertoc\s[\s\w\/\\.:\-]+/gi)) {
                if (match[0].toLowerCase().includes('-loaddll')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Execute/Tools/squirrel',
        description: 'Detects usage of the squirrel tool (MS Teams updater) to execute other code. This can be used to pivot to stronger payload.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes the --update, --updateRollback, or --processStart switches (used for execution)
            for (const match of cleaned.matchAll(/\b(?:squirrel|update)\s[\s\w\/\\.:\-]+/gi)) {
                const cmd = match[0].toLowerCase();
                if (cmd.includes('--update') || cmd.includes('--updaterollback') || cmd.includes('--processstart')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Execute/Tools/url.dll',
        description: 'Detects usage of url.dll to execute other code. This can be used to pivot to stronger payload.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes OpenURL or FileProtocolHandler arguments (used for execution)
            for (const match of cleaned.matchAll(/\burl\.dll\b[\s\w\/\\.:\-,]+/gi)) {
                const cmd = match[0].toLowerCase();
                if (cmd.includes('openurl') || cmd.includes('fileprotocolhandler')) {
                    yield match;
                }
            }
        },
        // This supports obfuscation of the form "foo" -> "^f^o^o"
        decode: ([cmd]) => cmd.replaceAll(/\^(.)/g, (_, value) => value)
    },
    {
        name: 'Payload/Execute/Tools/zipfldr.dll',
        description: 'Detects usage of zipfldr.dll to execute other code. This can be used to pivot to stronger payload.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes RouteTheCall argument (used for execution)
            for (const match of cleaned.matchAll(/\bzipfldr\.dll\b[\s\w\/\\.:\-,]+/gi)) {
                if (match[0].toLowerCase().includes('routethecall')) {
                    yield match;
                }
            }
        },
        // This supports obfuscation of the form "foo" -> "^f^o^o"
        decode: ([cmd]) => cmd.replaceAll(/\^(.)/g, (_, value) => value)
    },
    {
        name: 'Payload/Execute/Extensions/generic',
        description: 'Detects file extensions of common cross-platform executable formats. This rule tends to generate a lot of noise.',
        match: cleaned => cleaned.matchAll(/\.(?:py|class|jar|war|ear|rb)\b/gi)
    },
    {
        name: 'Payload/Execute/Extensions/Windows',
        description: 'Detects file extensions of common Windows-specific executable formats.',
        match: cleaned => cleaned.matchAll(/\.(?:bat|cmd|ps[12]|vb[sa]?|lnk|csx?|ws[cf])\b/gi)
    },
    {
        name: 'Payload/Execute/Extensions/Linux',
        description: 'Detects file extensions of common Linux-specific executable formats. This rule tends to generate a lot of noise due to embedded web servers that expose APIs via shell scripts.',
        match: cleaned => cleaned.matchAll(/\.sh\b/gi)
    },
    {
        name: 'Payload/Downloader/generic/Windows',
        description: 'Detects functions and utilities that are commonly used to download additional payloads on Windows systems.',
        match: cleaned => cleaned.matchAll(/\b(?:AppInstaller|CertReq|Certutil|cmdl32|Desktopimgdownldr|Diantz|Esentutl|Expand|Extrac32|Findstr|Finger|Ftp|GfxDownloadWrapper|IMEWDBLD|Makecab|MpCmdRun|OneDriveStandaloneUpdater|PrintBrm|Replace|Xwizard|Teams\/update|Squirrel|Ieexec)(?=\s)/gi)
    },
    {
        name: 'Payload/Downloader/bitsadmin',
        description: 'Detects usage of the bitsadmin tool to download files.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes the /addfile switch (used for downloading)
            for (const match of cleaned.matchAll(/\bbitsadmin\s[\s\w\/\\.:\-]+/gi)) {
                if (match[0].toLowerCase().includes('/addfile')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Downloader/certoc',
        description: 'Detects usage of the CertOC tool to download files.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes the -GetCACAPS switch (used for downloading)
            for (const match of cleaned.matchAll(/\bcertoc\s[\s\w\/\\.:\-]+/gi)) {
                if (match[0].toLowerCase().includes('-getcacaps')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Downloader/xwizard',
        description: 'Detects usage of the XWizard tool to download files.',
        *match(cleaned) {
            // Match the entire command line, and then check if it references the "RemoteApp and Desktop Connections" wizard which is actually used for downloading
            for (const match of cleaned.matchAll(/\bxwizard\s[\s\w\/\\.:\-]+/gi)) {
                const cmd = match[0].toLowerCase();
                if (cmd.includes('runwizard') && cmd.includes('{7940acf8-60ba-4213-a7c3-f3b400ee266d}')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Execute/Tools/squirrel',
        description: 'Detects usage of the squirrel tool (MS Teams updater) to download files.',
        *match(cleaned) {
            // Match the entire command line, and then check if it includes the --download switch (used for downloading)
            for (const match of cleaned.matchAll(/\b(?:squirrel|update)\s[\s\w\/\\.:\-]+/gi)) {
                if (match[0].toLowerCase().includes('--download')) {
                    yield match;
                }
            }
        }
    },
    {
        name: 'Payload/Downloader/Linux',
        description: 'Detects functions and utilities that are commonly used to download additional payloads on Linux systems.',
        match: cleaned => cleaned.matchAll(/\b(?:wget|curl|nc)[\s$]/gi)
    },
    {
        name: 'Payload/Downloader/netcat',
        description: 'Detects calls to netcat, which is commonly used to download payloads on embedded linux systems. This rule will attempt to capture all arguments including the target URL to assist further analysis.',
        match: cleaned => cleaned.matchAll(/\bnc(?:\s+[^&|;>\s]+)*(?:\s+[^&|;\s>]+){2}/gi)
    },
    {
        name: 'Payload/Downloader/wget',
        description: 'Detects calls to wget, which is commonly used to download payloads on Linux servers. This rule will attempt to capture all arguments including the target URL to assist further analysis.',
        match: cleaned => cleaned.matchAll(/\bwget(?:\s+[^&|;>\s]+)*\s+[^&|;\s>]+(?:\s+[^&|;\s>]+)*/gi)
    },
    {
        name: 'Payload/Downloader/curl',
        description: 'Detects calls to curl, which is commonly used to download payloads on Linux servers. This rule will attempt to capture all arguments including the target URL to assist further analysis.',
        match: cleaned => cleaned.matchAll(/\bcurl(?:\s+[^&|;>\s]+)*\s+[^&|;\s>]+(?:\s+[^&|;\s>]+)*/gi)
    },
    {
        name: 'Payload/Stealth/Hiding',
        description: 'Detects attempts to hide activity by manipulating commands and tools.',
        match: cleaned => cleaned.matchAll(/\bWsl\b/gi)
    },
    {
        name: 'Payload/Stealth/Log Tampering',
        description: 'Detects attempts to hide activity by tampering with log files.',
        match: cleaned => cleaned.matchAll(/\b(?:clear|cls|history)\b/gi)
    },

    {
        name: 'Obfuscation/Interpolation',
        description: 'Detects interpolated strings, which are commonly used to obfuscate shellcode. Interpolation is also commonly used to leak sensitive information. This rule generates a LOT of noise when scanning attempts to exploit Log4Shell.',
        match: cleaned => cleaned.matchAll(/\$+\{[\w:-]*\w+[\w:-]*}/g)
    },

    {
        name: 'Vulnerability/generic/traversal',
        description: 'Insecure web servers will allow access to private files by inserting ../ into the URL.',
        match: cleaned => cleaned.matchAll(/\.*\/+(?:\.{2,}\/+)+\.*/g)
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
        name: 'Vulnerability/Wordpress/plugin/user-photo/v0.9.4/CVE-2013-1916 Arbitrary File Upload',
        description: 'Wordpress plugin user-photo versions 0.9.4 and older are vulnerable to arbitrary file upload due to lack of validation on uploaded images.',
        links: [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1916',
            'https://www.exploit-db.com/exploits/16181'
        ],
        cve: 'CVE-2013-1916',
        match: cleaned => cleaned.matchAll(/\bwp-content\/uploads\/userphoto\b/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/simple-ads-manager/v2.9.8.125/CVE-2017-20095 Object Injection',
        description: 'Wordpress plugin simple-ads-manager version 2.9.8.125 and older are vulnerable to Object Injection via untrusted deserialization. This can potentially lead to RCE.',
        links: [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-20095',
            'https://seclists.org/fulldisclosure/2017/Feb/80',
            'https://sumofpwn.nl/advisory/2016/simple_ads_manager_wordpress_plugin_unauthenticated_php_object_injection_vulnerability.html'
        ],
        cve: 'CVE-2017-20095',
        match: cleaned => cleaned.matchAll(/\/sam-ajax-loader\.php\b/gi)
    },
    {
        name: 'Vulnerability/Wordpress/plugin/new-stat-plugin/v1.2.4/CVE-2017-20094 XSS',
        description: 'Wordpress plugin new-stat-plugin version 1.2.4 and older are vulnerable to XSS through the page URL and referer header. Since the vulnerability can be triggered from any page, this rule matches the pages where the injected script can be triggered.',
        links: [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-20094',
            'https://sumofpwn.nl/advisory/2016/persistent_cross_site_scripting_in_the_wordpress_newstatpress_plugin.html'
        ],
        cve: 'CVE-2017-20094',
        match: cleaned => cleaned.matchAll(/\/wp-admin\/admin\.php\?[\w%_.\-=&\\\/]*page=nsp_(?:main|visits)/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32391 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via view_action.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32391.md' ],
        cve: 'CVE-2022-32391',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/actions\/view_action\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32392 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_action.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32392.md' ],
        cve: 'CVE-2022-32392',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/actions\/manage_action\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32393 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via view_cell.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32393.md' ],
        cve: 'CVE-2022-32393',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/cells\/view_cell\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32394 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via view_inmate.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32394.md' ],
        cve: 'CVE-2022-32394',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/inmates\/view_inmate\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32395 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_crime.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32395.md' ],
        cve: 'CVE-2022-32395',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/crimes\/manage_crimes\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32396 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_visit.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32396.md' ],
        cve: 'CVE-2022-32396',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/visits\/manage_visit\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32397 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via view_visit.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32397.md' ],
        cve: 'CVE-2022-32397',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/visits\/view_visit\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32398 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_cell.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32398.md' ],
        cve: 'CVE-2022-32398',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/cells\/manage_cell\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32399 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via view_crime.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32399.md' ],
        cve: 'CVE-2022-32399',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/crimes\/view_crime\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32400 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_user.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32400.md' ],
        cve: 'CVE-2022-32400',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/user\/manage_user\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32401 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_privilege.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32401.md' ],
        cve: 'CVE-2022-32401',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/inmates\/manage_privilege\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32402 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_prison.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32402.md' ],
        cve: 'CVE-2022-32402',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/prisons\/manage_prison\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32403 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_record.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32403.md' ],
        cve: 'CVE-2022-32403',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/inmates\/manage_record\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32404 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via manage_inmate.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32404.md' ],
        cve: 'CVE-2022-32404',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/inmates\/manage_inmate\.php\b/gi)
    },
    {
        name: 'Vulnerability/Prison Management System/v1.0/CVE-2022-32405 SQLi',
        description: 'Prison Management System version 1.0 and older are vulnerable to SQL injection via view_prison.php.',
        links: [ 'https://github.com/Dyrandy/BugBounty/blob/main/pms/cve-2022-32405.md' ],
        cve: 'CVE-2022-32405',
        match: cleaned => cleaned.matchAll(/\bpms\/admin\/prisons\/view_prison\.php\b/gi)
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
        name: 'Vulnerability/Concrete/v8.5.7/CVE-2022-30117 Arbitrary File Delete',
        description: 'Concrete CMS versions 9.0 through 9.0.2, version 8.5.7, and older are vulnerable to Arbitrary File Deletion through directory traversal in /ccm/system/file/upload.',
        links: [ 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30117' ],
        cve: 'CVE-2022-30117',
        match: cleaned => cleaned.matchAll(/\bindex\.php\/ccm\/system\/file\/upload\b/gi)
    },
    {
        name: 'Vulnerability/Concrete/v8.5.7/CVE-2022-30118 XSS',
        description: 'Concrete CMS versions 9.0 through 9.0.2, version 8.5.7, and older are vulnerable to XSS in /dashboard/system/express/entities/forms/save_control/. XSS is only affective against older browsers.',
        links: [ 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30118' ],
        cve: 'CVE-2022-30118',
        match: cleaned => cleaned.matchAll(/\bdashboard\/system\/express\/entities\/forms\/save_control\b/gi)
    },
    {
        name: 'Vulnerability/Concrete/v8.5.7/CVE-2022-30119 XSS',
        description: 'Concrete CMS versions 9.0 through 9.0.2, version 8.5.7, and older are vulnerable to XSS in /dashboard/reports/logs/view. XSS is only affective against older browsers.',
        links: [ 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30119' ],
        cve: 'CVE-2022-30119',
        match: cleaned => cleaned.matchAll(/\bdashboard\/reports\/logs\/view\b/gi)
    },
    {
        name: 'Vulnerability/Concrete/v8.5.7/CVE-2022-30120 XSS',
        description: 'Concrete CMS versions 9.0 through 9.0.2, version 8.5.7, and older are vulnerable to XSS in /dashboard/blocks/stacks/view_details. XSS is only affective against older browsers.',
        links: [ 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30120' ],
        cve: 'CVE-2022-30120',
        match: cleaned => cleaned.matchAll(/\bdashboard\/blocks\/stacks\/view_details\b/gi)
    },

    {
        name: 'Malware/Mozi',
        description: 'The Mozi botnet targets embedded IoT (Internet of Things) devices using known but frequently unpatched vulnerabilities. This rule attempts to detect it by recognizing its most common filenames.',
        links: [ 'https://blog.lumen.com/new-mozi-malware-family-quietly-amasses-iot-bots/' ],
        match: cleaned => cleaned.matchAll(/\bMozi\.\w+\b/gi)
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