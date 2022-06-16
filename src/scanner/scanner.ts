/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import ReadableStream = NodeJS.ReadableStream;
import WritableStream = NodeJS.WritableStream;
import {Rule} from "../rule/rule.js";
import {allRules} from "../rule/rules.js";
import readline from "node:readline";
import {Interface} from "readline";
import {Cleaner} from "../cleaner/cleaner.js";
import {Sanitizer} from "../sanitizer/sanitizer.js";
import {allCleaners} from "../cleaner/cleaners.js";
import {allSanitizers} from "../sanitizer/sanitizers.js";

/**
 * Scans a stream for matches and 
 */
export class Scanner {
    private readonly options: ScannerOpts;

    private readonly output: WritableStream;
    private readonly rl: Interface;
    
    private nextLineNum: number = 0;
    
    constructor(input: ReadableStream, output: WritableStream, opts: ScannerOpts = defaultScannerOpts) {
        this.output = output;
        this.options = opts;

        // Setup Readline interface
        this.rl = readline.createInterface({ input });
        this.rl.on('line', line => this.onLine(line));
        output.on('close', () => this.close());
        output.on('error', e => {
            // This is expected if the output is closed while we are writing multiple matches.
            // The "close" event won't process until after the current line is done.
            // As a workaround, we can silently ignore EPIPE errors until the close event is fired.
            if (e.code !== 'EPIPE') {
                throw e;
            }
        });

        // Write TSV header if enabled.
        // This is done here because:
        // 1. It must happen before any matches are written
        // 2. It must happen even if no matches are found
        if (opts.includeTsvHeader) {
            this.writeTsvHeader();
        }
    }
    
    private onLine(rawLine: string): void {
        // Run all cleaners
        const cleanedLine = this.cleanLine(rawLine);

        // Run all rules
        this.scanLine(cleanedLine, rawLine);

        // Increment line number, even if we don't match
        this.nextLineNum++;
    }

    private cleanLine(rawLine: string): string {
        while (true) {
            const newLine = this.options.cleaners.reduce((l, cleaner) => cleaner(l), rawLine);
            if (newLine === rawLine) {
                break;
            }
            rawLine = newLine;
        }
        return rawLine;
    }

    private scanLine(cleanedLine: string, rawLine: string) {
        // Try each rule
        for (const rule of this.options.rules) {
            // Apply it and find all matches
            const matches = rule.match(cleanedLine, rawLine);

            // Decode and print all matches
            for (const match of matches) {
                // Decode the match
                const decodedMatch = Scanner.decodeMatch(rule, match, cleanedLine, rawLine);

                // Write output
                this.writeMatch(rule, decodedMatch, cleanedLine, rawLine, this.nextLineNum);
            }
        }
    }

    private static decodeMatch(rule: Rule, match: RegExpMatchArray, cleanedLine: string, rawLine: string): string {
        if (rule.decode) {
            // Use rule-specific decoder if defined
            return rule.decode(match, cleanedLine, rawLine);
        } else {
            // Otherwise, fall back to the raw match
            return match[0];
        }
    }

    private sanitize(str: string): string {
        return this.options.sanitizers.reduce((val, san) => san(val), str)
    }

    private writeMatch(rule: Rule, match: string, cleaned: string, raw: string, lineNumber: number): void {
        const log = this.getMatchString(rule, match, cleaned, raw, lineNumber);
        this.output.write(log);
        this.output.write('\n');
    }

    private getMatchString(rule: Rule, match: string, cleanedLine: string, rawLine: string, lineNumber: number): string {
        // Build array of tailing "detail" parts.
        // These are similar enough that they can be handled by common logic.
        const otherParts: string[] = [
            this.sanitize(match)
        ];
        if (this.options.includeCleaned) {
            otherParts.push(this.sanitize(cleanedLine));
        }
        if (this.options.includeVerbose) {
            otherParts.push(this.sanitize(rawLine));
        }
        if (this.options.includeDescription) {
            otherParts.push(rule.description);
        }
        if (this.options.includeCVE) {
            otherParts.push(rule.cve ?? '');
        }
        if (this.options.includeLinks) {
            otherParts.push(rule.links?.join(',') ?? '');
        }

        if (this.options.isTsv) {
            // Prepend name/line, and then join all into a TSV line
            return [ rule.name, String(lineNumber) ].concat(otherParts).join('\t');
        } else {
            // 1. Prepend formatted name/line
            // 2. Filter empty parts
            // 3. Wrap other parts in {}
            // 4. Join all together into the formatted output line
            return [ rule.name + ':', String(lineNumber).padStart(9, ' ') ].concat(otherParts.filter(p => p !== '').map(p => `{${p}}`)).join(' ');
        }
    }

    private writeTsvHeader(): void {
        // Add hardcoded parts
        const parts = [
            'Rule Name',
            'Line Index',
            'Matched Text',
        ];

        // Add optional parts
        if (this.options.includeCleaned) {
            parts.push('Cleaned Line');
        }
        if (this.options.includeVerbose) {
            parts.push('Raw Line');
        }
        if (this.options.includeDescription) {
            parts.push('Rule Description');
        }
        if (this.options.includeCVE) {
            parts.push('Related CVE');
        }
        if (this.options.includeLinks) {
            parts.push('Info Links');
        }

        // Write it
        this.output.write(parts.join('\t'));
        this.output.write('\n');
    }
    
    public close(): void {
        this.rl.close();
    }
}

export interface ScannerOpts {
    rules: readonly Rule[];
    cleaners: readonly Cleaner[];
    sanitizers: readonly Sanitizer[];
    isTsv: boolean;
    includeTsvHeader: boolean;
    includeVerbose: boolean;
    includeCleaned: boolean;
    includeDescription: boolean;
    includeCVE: boolean;
    includeLinks: boolean;
}

export const defaultScannerOpts: ScannerOpts = {
    rules: allRules,
    cleaners: allCleaners,
    sanitizers: allSanitizers,
    isTsv: false,
    includeTsvHeader: false,
    includeCleaned: true,
    includeVerbose: false,
    includeDescription: false,
    includeCVE: false,
    includeLinks: false
}

/**
 * Creates a scanner instance that is attached to standard input and output.
 */
export function createStdScanner(): Scanner {
    return new Scanner(process.stdin, process.stdout);
}