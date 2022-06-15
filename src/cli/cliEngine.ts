/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {defaultScannerOpts, Scanner, ScannerOpts} from "../scanner/scanner.js";
import ReadableStream = NodeJS.ReadableStream;
import WritableStream = NodeJS.WritableStream;
import {Args} from "./args.js";
import {allRules} from "../rule/rules.js";
import {logScanVersion} from "../index.js";

export function runCli(cliArgs: string[], input: ReadableStream = process.stdin, output: WritableStream = process.stdout): void {
    const args = new Args(cliArgs);

    // Handle "print-and-exit" commands
    if (args.getFlag('--help')) {
        runHelpCommand(output);
    } else if (args.getFlag('--version')) {
        runVersionCommand(output);
    } else if (args.getFlag('--list-rules')) {
        runListRulesCommand(output);
    } else {
        // Run normal scan process
        const scannerOpts = parseScannerOpts(args);

        // Create and run scanner
        new Scanner(input, output, scannerOpts);
    }
}

export function runHelpCommand(output: WritableStream) {
    output.write('Scans webserver log lines to detect suspicious behavior.\n')
    output.write('Logs should be piped through standard input, one line per log.\n');
    output.write('Findings will be printed to stdout, one line per finding.\n');
    output.write('All output is automatically sanitized to remove non-ascii-printable characters.\n');
    output.write('\n');
    output.write('Depending on flags, output may contain the following components:\n');
    output.write('Finding:   Name of the rule that matched the output.\n');
    output.write('Index:     Index (line number) of the line that was matched. This is counted by lines received as piped input, not lines in the original file.\n');
    output.write('Match:     Portion of the line that was detected. This is automatically decoded / deobfuscated, if possible.\n');
    output.write('Line:      Entire content of the matched line. This is automatically decoded / deobfuscated, if possible.\n');
    output.write('Raw:       Same as "line", but NOT decoded. Only the standard sanitization is applied.\n');
    output.write('\n');
    output.write('Standard output formats:\n');
    output.write('|TSV|Raw|Clean|Format                                           |Notes                               |\n');
    output.write('| X | X |  X  | [Finding]\\t[Index]\\t[Match]\\t[Line]\\t[Raw]      |                                    |\n');
    output.write('| X |   |  X  | [Finding]\\t[Index]\\t[Match]\\t[Line]             |                                    |\n');
    output.write('|   | X |  X  | [Finding]: [Index] {[Match]} {[Line]} {[Raw]}   |Index is left-padded to 9 characters|\n');
    output.write('|   |   |  X  | [Finding]: [Index] {[Match]} {[Line]}           |Index is left-padded to 9 characters|\n');
    output.write('| X | X |     | [Finding]\\t[Index]\\t[Match]\\t[Raw]              |                                    |\n');
    output.write('| X |   |     | [Finding]\\t[Index]\\t[Match]                     |                                    |\n');
    output.write('|   | X |     | [Finding]: [Index] {[Match]} {[Raw]}            |Index is left-padded to 9 characters|\n');
    output.write('|   |   |     | [Finding]: [Index] {[Match]}                    |Index is left-padded to 9 characters|\n');
    output.write('\n');
    output.write('Usage: find-suspicious-logs [options]\n');
    output.write('--help                 Print help and exit.\n');
    output.write('--version              Print version and exit.\n');
    output.write('--list-rules           List all rules and exit.\n');
    output.write('--tsv                  Output in TSV (tab-delimited) format.\n');
    output.write('--cleaned=<Y/N>        Include the entire cleaned, decoded line in the output. Defaults to Y (on).\n')
    output.write('--raw=<Y/N>            Include the entire raw, un-decoded line in the output. Defaults to N (off)\n');
    output.write('--include=<patterns>   Patterns to include rules (comma separated). Only matching rules will be run.\n');
    output.write('--exclude=<patterns>   Patterns to exclude rules (comma separated). Overrides --include option.\n');
}

export function runVersionCommand(output: WritableStream) {
    output.write(logScanVersion);
    output.write('\n');
}

export function runListRulesCommand(output: WritableStream) {
    // TODO respect --include and --exclude arguments
    
    // Sort rules alphabetically
    const sortedRules = Array.from(allRules)
        .sort((a, b) => a.name.localeCompare(b.name));

    // Print all rules
    for (const rule of sortedRules) {
        output.write(rule.name);
        output.write('\n');
    }
}

export function parseScannerOpts(args: Args): ScannerOpts {
    const opts = Object.assign({}, defaultScannerOpts);

    // Get flags
    opts.isTsv = args.getFlag('--tsv');
    opts.includeVerbose = args.getBool('--raw', 'y', false);
    opts.includeCleaned = args.getBool('--cleaned', 'y', true);

    // Filter rules
    const includes = args.getAllStrings('--include').flatMap(include => include.split(','));
    const excludes = args.getAllStrings('--exclude').flatMap(exclude => exclude.split(','));
    opts.rules = allRules.filter(rule => {
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

    return opts;
}