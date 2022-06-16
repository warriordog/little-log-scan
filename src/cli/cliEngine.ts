/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {defaultScannerOpts, Scanner, ScannerOpts} from "../scanner/scanner.js";
import ReadableStream = NodeJS.ReadableStream;
import WritableStream = NodeJS.WritableStream;
import {Args} from "./args.js";
import {allRules} from "../rule/rules.js";
import {logScanVersion, Rule} from "../index.js";

export function runCli(cliArgs: string[], input: ReadableStream = process.stdin, output: WritableStream = process.stdout): void {
    const args = new Args(cliArgs);

    // Handle "print-and-exit" commands
    if (args.getFlag('--help')) {
        runHelpCommand(output);
    } else if (args.getFlag('--version')) {
        runVersionCommand(output);
    } else if (args.getFlag('--list-rules')) {
        runListRulesCommand(output, args);
    } else {
        // Run normal scan process
        const scannerOpts = parseScannerOpts(args);

        // Create and run scanner
        new Scanner(input, output, scannerOpts);
    }
}

export function runHelpCommand(output: WritableStream): void {
    output.write('Scans webserver log lines to detect suspicious behavior.\n')
    output.write('Logs should be piped through standard input, one line per log.\n');
    output.write('Findings will be printed to stdout, one line per finding.\n');
    output.write('All output is automatically sanitized to remove non-ascii-printable characters.\n');
    output.write('\n');
    output.write('Depending on flags, output may contain the following components:\n');
    output.write('* Finding: Name of the rule that matched the output.\n');
    output.write('* Index:  Index (line number) of the line that was matched. This is counted by lines received as piped input, not lines in the original file.\n');
    output.write('* Match:  Portion of the line that was detected. This is automatically decoded / deobfuscated, if possible.\n');
    output.write('* Line:   Entire content of the matched line. This is automatically decoded / deobfuscated, if possible.\n');
    output.write('* Raw:    Same as "line", but NOT decoded. Only the standard sanitization is applied.\n');
    output.write('* Desc:   Description of the rule that matched.\n');
    output.write('* CVE:    Associated CVE number, if applicable.\n');
    output.write('* Links:  URLs to related information.\n');
    output.write('\n');
    output.write('Output will always start with the Finding, Index, and Match.\n');
    output.write('The remaining options, if enabled, will appear in the order Line, Raw, Desc, CVE, and finally Links.\n');
    output.write('Any disabled options will be skipped.\n');
    output.write('In TSV mode, the output is not formatted beyond the required TSV format (tabs (`\t`) between cells, newlines (`\n`) between rows).\n');
    output.write('Standard output mode will apply additional formatting for readability.\n');
    output.write('\n');
    output.write('Usage: little-log-scan [options]\n');
    output.write('--help                 Print help and exit.\n');
    output.write('--version              Print version and exit.\n');
    output.write('--list-rules           List all rules that are included by the specified include/exclude patterns.\n');
    output.write('--tsv                  Output in TSV (tab-delimited) format.\n');
    output.write('--cleaned=<Y/N>        Include the entire cleaned, decoded line in the output. Defaults to Y (on).\n')
    output.write('--raw=<Y/N>            Include the entire raw, un-decoded line in the output. Defaults to N (off)\n');
    output.write('--include=<patterns>   Patterns to include rules (comma separated). Only matching rules will be run.\n');
    output.write('--exclude=<patterns>   Patterns to exclude rules (comma separated). Overrides --include option.\n');
    output.write('--rule-desc=<Y/N>      Include rule descriptions in the output.\n');
    output.write('--rule-cve=<Y/N>       Include a list of matching CVEs in the output.\n');
    output.write('--rule-links=<Y/N>     Include links to vulnerability details in the output.\n');
}

export function runVersionCommand(output: WritableStream): void {
    output.write(logScanVersion);
    output.write('\n');
}

export function runListRulesCommand(output: WritableStream, args: Args): void {
    // Get rules based on args
    const rules = getRulesFromArgs(args)

    // Sort rules alphabetically
    const sortedRules = rules.sort((a, b) => a.name.localeCompare(b.name));

    // Print all rules
    output.write(`Matched ${sortedRules.length} rules:\n`);
    for (const rule of sortedRules) {
        output.write(rule.name);
        output.write('\n');
    }
}

export function parseScannerOpts(args: Args): ScannerOpts {
    // Preload default options
    const opts = Object.assign({}, defaultScannerOpts);

    // Override based on CLI flags
    opts.isTsv = args.getFlag('--tsv');
    opts.includeVerbose = args.getBool('--raw', 'y', false);
    opts.includeCleaned = args.getBool('--cleaned', 'y', true);
    opts.includeDescription = args.getBool('--rule-desc', 'y', false);
    opts.includeCVE = args.getBool('--rule-cve', 'y', false);
    opts.includeLinks = args.getBool('--rule-links', 'y', false);
    opts.rules = getRulesFromArgs(args);

    return opts;
}

export function getRulesFromArgs(args: Args): Rule[] {
    // Read all include and exclude arguments
    const includes = args.getAllStrings('--include').flatMap(include => include.split(','));
    const excludes = args.getAllStrings('--exclude').flatMap(exclude => exclude.split(','));

    // Filter rules
    return allRules.filter(rule => {
        // If includes are specified, AND none of them match, then exclude this rule.
        if (includes.length > 0 && !includes.some(include => rule.name.includes(include))) {
            return false;
        }

        // If any exclude matches, then exclude this rule
        // noinspection RedundantIfStatementJS
        if (excludes.some(exclude => rule.name.includes(exclude))) {
            return false;
        }

        return true;
    });
}