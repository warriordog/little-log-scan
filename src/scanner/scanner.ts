/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import ReadableStream = NodeJS.ReadableStream;
import readline from "node:readline";
import {Interface} from "readline";
import {Matcher} from "./matcher.js";
import {Writer} from "./writer.js";
import {TypedEmitter} from "tiny-typed-emitter";

/**
 * Continuously reads from a stream and scans it for matches.
 */
export class Scanner extends TypedEmitter<ScannerEvents> {
    private readonly matcher: Matcher;
    private readonly writer: Writer;
    private readonly rl: Interface;
    
    constructor(input: ReadableStream, matcher: Matcher, writer: Writer) {
        super();
        this.matcher = matcher;
        this.writer = writer;

        // Setup Readline interface
        this.rl = readline.createInterface({ input });
        this.rl.on('line', line => this.onLine(line));
        writer.on('close', () => this.close());
        writer.on('error', error => this.emit('error', error));
    }
    
    private onLine(rawLine: string): void {
        // Run matcher
        const matchInfo = this.matcher.matchLine(rawLine);

        // Write all matches
        if (matchInfo) {
            this.writer.writeMatches(matchInfo);
        }
    }
    
    public close(): void {
        this.rl.close();
        this.emit('close');
    }
}

export interface ScannerEvents {
    close: () => void;
    error: (error: Error) => void;
}