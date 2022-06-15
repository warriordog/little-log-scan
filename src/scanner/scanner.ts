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
    private readonly rules: readonly Rule[];
    private readonly cleaners: readonly Cleaner[];
    private readonly sanitizers: readonly Sanitizer[];
    private readonly isTsv: boolean;
    private readonly includeVerbose: boolean;
    private readonly includeCleaned: boolean;

    private readonly output: WritableStream;
    private readonly rl: Interface;
    
    private nextLineNum: number = 0;
    
    constructor(input: ReadableStream, output: WritableStream, opts: ScannerOpts = defaultScannerOpts) {
        this.output = output;

        this.rules = opts.rules;
        this.cleaners = opts.cleaners;
        this.sanitizers = opts.sanitizers;
        this.isTsv = opts.isTsv;
        this.includeVerbose = opts.includeVerbose;
        this.includeCleaned = opts.includeCleaned;

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
            const newLine = this.cleaners.reduce((l, cleaner) => cleaner(l), rawLine);
            if (newLine === rawLine) {
                break;
            }
            rawLine = newLine;
        }
        return rawLine;
    }

    private scanLine(cleanedLine: string, rawLine: string) {
        // Try each rule
        for (const rule of this.rules) {
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

    private sanitize(strings: TemplateStringsArray, ...values: unknown[]): string {
        const parts = [ strings[0] ];
        for (let i = 0; i < values.length; i++) {
            const value = this.sanitizers.reduce((val, san) => san(val), String(values[i]));
            parts.push(value);
            parts.push(strings[i + 1]);
        }
        return parts.join('');
    }

    private writeMatch(rule: Rule, match: string, cleaned: string, raw: string, lineNumber: number): void {
        const log = this.getMatchString(rule, match, cleaned, raw, lineNumber);
        this.output.write(log);
        this.output.write('\n');
    }

    private getMatchString(rule: Rule, match: string, cleanedLine: string, rawLine: string, lineNumber: number): string {
        if (this.isTsv) {
            if (this.includeCleaned) {
                if (this.includeVerbose) {
                    return this.sanitize`${rule.name}\t${lineNumber}\t${match}\t${cleanedLine}\t${rawLine}`;
                } else {
                    return this.sanitize`${rule.name}\t${lineNumber}\t${match}\t${cleanedLine}`;
                }
            } else {
                if (this.includeVerbose) {
                    return this.sanitize`${rule.name}\t${lineNumber}\t${match}\t${rawLine}`;
                } else {
                    return this.sanitize`${rule.name}\t${lineNumber}\t${match}`;
                }
            }
        } else {
            if (this.includeCleaned) {
                if (this.includeVerbose) {
                    return this.sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}} {${cleanedLine}} {${rawLine}}`;
                } else {
                    return this.sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}} {${cleanedLine}}`;
                }
            } else {
                if (this.includeVerbose) {
                    return this.sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}} {${rawLine}}`;
                } else {
                    return this.sanitize`${rule.name}: ${String(lineNumber).padStart(9, ' ')} {${match}}`;
                }
            }
        }
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
    includeVerbose: boolean;
    includeCleaned: boolean;
}

export const defaultScannerOpts: ScannerOpts = {
    rules: allRules,
    cleaners: allCleaners,
    sanitizers: allSanitizers,
    isTsv: false,
    includeCleaned: true,
    includeVerbose: false
}

/**
 * Creates a scanner instance that is attached to standard input and output.
 */
export function createStdScanner(): Scanner {
    return new Scanner(process.stdin, process.stdout);
}