/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Rule} from "../rule/rule.js";
import {Cleaner} from "../cleaner/cleaner.js";
import {allRules} from "../rule/rules.js";
import {allCleaners} from "../cleaner/cleaners.js";
import {MatchInfo} from "./matchInfo.js";
import {Match} from "./match.js";

/**
 * Processes lines of text to find matches.
 * Runs provided cleaners to decode input, then runs all provided rules to find matches.
 */
export class Matcher {
    private readonly options: MatcherOpts;
    private nextLineNum: number = 0;

    public constructor(options: MatcherOpts = defaultMatcherOpts) {
        this.options = options;
    }

    /**
     * Scan a line for matches
     * @param rawLine Return a match info containing all matches, or undefined if nothing matched.
     */
    public matchLine(rawLine: string): MatchInfo | undefined {
        // Run all cleaners
        const cleanedLine = this.cleanLine(rawLine);

        // Run all rules to find matches
        const matches = this.findMatches(cleanedLine, rawLine);

        // Save and increment line number
        const lineNumber = this.nextLineNum;
        this.nextLineNum++;

        // Return any matches
        if (matches.length > 0) {
            return {
                cleanedLine,
                rawLine,
                lineNumber,
                matches
            };
        } else {
            // No matches
            return undefined;
        }
    }

    private cleanLine(rawLine: string): string {
        // Loop until its fully sanitized
        while (true) {
            // Record the starting value for comparison
            const lastLine = rawLine;

            // Run each cleaner over the current input
            for (const cleaner of this.options.cleaners) {
                rawLine = cleaner(rawLine);
            }

            // Stop looping once the output has settled
            if (rawLine === lastLine) {
                return rawLine;
            }
        }
    }

    private findMatches(cleanedLine: string, rawLine: string): Match[] {
        const findings = [];

        // Try each rule
        for (const rule of this.options.rules) {
            // Apply it and find all matches
            const matches = rule.match(cleanedLine, rawLine);

            // Decode and print all matches
            for (const match of matches) {
                // Decode the match
                const decodedMatch = decodeMatch(rule, match, cleanedLine, rawLine);

                // Add to collection
                findings.push({
                    rule,
                    match: decodedMatch
                });
            }
        }

        return findings;
    }
}

function decodeMatch(rule: Rule, match: RegExpMatchArray, cleanedLine: string, rawLine: string): string {
    if (rule.decode) {
        // Use rule-specific decoder if defined
        return rule.decode(match, cleanedLine, rawLine);
    } else {
        // Otherwise, fall back to the raw match
        return match[0];
    }
}

export interface MatcherOpts {
    rules: readonly Rule[];
    cleaners: readonly Cleaner[];
}

export const defaultMatcherOpts: Readonly<MatcherOpts> = {
    rules: allRules,
    cleaners: allCleaners
}