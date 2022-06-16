/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Sanitizer} from "../sanitizer/sanitizer.js";
import {allSanitizers} from "../sanitizer/sanitizers.js";
import {TypedEmitter} from "tiny-typed-emitter";
import WritableStream = NodeJS.WritableStream;
import {MatchInfo} from "./matchInfo.js";
import {Match} from "./match.js";

/**
 * Writes matches to an output stream.
 * Also responsible for sanitization and formatting.
 */
export class Writer extends TypedEmitter<WriterEvents> {
    private readonly options: WriterOpts;
    private readonly output: WritableStream;

    public constructor(output: WritableStream, options: WriterOpts = defaultWriterOpts) {
        super();
        this.options = options;
        this.output = output;

        output.on('close', () => this.emit('close'));
        output.on('error', e => {
            // This is expected if the output is closed while we are writing multiple matches.
            // The "close" event won't process until after the current line is done.
            // As a workaround, we can convert EPIPE errors to close() events, which has the side effect of ignoring the error.
            if (e.code === 'EPIPE') {
                this.emit('close');
            } else {
                this.emit('error', e);
            }
        });


        // Write TSV header if enabled.
        // This is done here because:
        // 1. It must happen before any matches are written
        // 2. It must happen even if no matches are found
        if (options.includeTsvHeader) {
            this.writeTsvHeader();
        }
    }

    /**
     * Write all matches in a set.
     * @param info Match set to record.
     */
    public writeMatches(info: MatchInfo): void {
        // Unpack and sanitize details
        const sanitizedCleanedLine = this.sanitize(info.cleanedLine);
        const sanitizedRawLine = this.sanitize(info.rawLine);
        const lineNumber = info.lineNumber;

        // Write each match
        for (const match of info.matches) {
            const log = this.getMatchString(sanitizedCleanedLine, sanitizedRawLine, lineNumber, match);
            this.output.write(log);
            this.output.write('\n');
        }
    }

    private getMatchString(sanitizedCleanedLine: string, sanitizedRawLine: string, lineNumber: number, match: Match): string {
        // Build array of tailing "detail" parts.
        // These are similar enough that they can be handled by common logic.
        const otherParts: string[] = [
            this.sanitize(match.match)
        ];
        if (this.options.includeCleaned) {
            otherParts.push(sanitizedCleanedLine);
        }
        if (this.options.includeVerbose) {
            otherParts.push(sanitizedRawLine);
        }
        if (this.options.includeDescription) {
            otherParts.push(match.rule.description);
        }
        if (this.options.includeCVE) {
            otherParts.push(match.rule.cve ?? '');
        }
        if (this.options.includeLinks) {
            otherParts.push(match.rule.links?.join(',') ?? '');
        }

        if (this.options.isTsv) {
            // Prepend name/line, and then join all into a TSV line
            return [ match.rule.name, String(lineNumber) ].concat(otherParts).join('\t');
        } else {
            // 1. Prepend formatted name/line
            // 2. Filter empty parts
            // 3. Wrap other parts in {}
            // 4. Join all together into the formatted output line
            return [ match.rule.name + ':', String(lineNumber).padStart(9, ' ') ].concat(otherParts.filter(p => p !== '').map(p => `{${p}}`)).join(' ');
        }
    }

    private sanitize(str: string): string {
        for (const sanitizer of this.options.sanitizers) {
            str = sanitizer(str);
        }
        return str;
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
}

export interface WriterEvents {
    close: () => void;
    error: (error: Error) => void;
}

export interface WriterOpts {
    sanitizers: readonly Sanitizer[];
    isTsv: boolean;
    includeTsvHeader: boolean;
    includeVerbose: boolean;
    includeCleaned: boolean;
    includeDescription: boolean;
    includeCVE: boolean;
    includeLinks: boolean;
}

export const defaultWriterOpts: Readonly<WriterOpts> = {
    sanitizers: allSanitizers,
    isTsv: false,
    includeTsvHeader: false,
    includeCleaned: true,
    includeVerbose: false,
    includeDescription: false,
    includeCVE: false,
    includeLinks: false
};