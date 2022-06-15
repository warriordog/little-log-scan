/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Cleaner} from "./cleaner.js";

export const allCleaners: readonly Cleaner[] = [
    // Align slashes
    line => line.replaceAll(/\\/g, '/'),

    // Decode percent encoding
    line => line.replaceAll(/%([\dA-Fa-f]{2})/g, (match, hex) => {
        const asciiValue = parseInt(hex, 16);
        return String.fromCharCode(asciiValue);
    }),

    // Decode HTTP Basic auth header
    line => line.replaceAll(/\b(Basic\s+)([A-Za-z\d+\/=]+)/gi, (match, prefix, b64) => {
        try {
            // Make sure to put the prefix back
            return prefix + Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    }),

    // Decode Log4j expressions
    // 2022-06-10: Some of these allow symbols in the latter part
    line => line.replaceAll(/\$+\{\s*[\w:]*:-([^$}]+)\s*}/g, (_, char) => char), // ${foo:-a}, ${::-a}, and ${foo:bar:-a} formats
    line => line.replaceAll(/\$+\{\s*(upper|lower):([^$}]+)\s*}/gi, (_, operator, char) => { // ${lower:a} and ${upper:a} formats
        const op = operator.toLowerCase();
        if (op === 'lower') return char.toLowerCase();
        if (op === 'upper') return char.toUpperCase();
        return char;
    }),
    line => line.replaceAll(/\$+(upper|lower)\s*\{([^$}]+)}\s*}/gi, (_, operator, char) => { // $$lower{a} and $$upper{a} formats
        const op = operator.toLowerCase();
        if (op === 'lower') return char.toLowerCase();
        if (op === 'upper') return char.toUpperCase();
        return char;
    }),
    line => line.replaceAll(/\$+\{\s*base64:([A-Za-z\d+\/=]+)\s*}/gi, (match, b64) => { // ${base64:==} format
        try {
            return Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    }),
    line => line.replaceAll(/\/base64\/([A-Za-z\d+\/=]+)/gi, (match, b64) => { // /Base64/abc format
        try {
            // Make sure to put the / back
            return '/' + Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    }),

    // Decode TVT ${IFS} inserts
    line => {
        // Try to limit to this one device
        if (/\/editBlackAndWhiteList/i.test(line)) {
            // Replace ${IFS} with a space
            return line.replaceAll(/\$\{\s*IFS\s*}/gi, ' ');
        } else {
            return line;
        }
    },

    // Decode calls to md5sum. Current only handles echo piped to md5sum.
    line => line.replaceAll(/\b(echo(?:\s+[\-\w]+)*\s)([A-Za-z\d+\/=]+)\s*\|\s*md5sum(?:\s+[\-\w]+)*/gi, (match, prefix, b64) => {
        try {
            return prefix + Buffer.from(b64, 'base64').toString('utf-8');
        } catch {
            return match;
        }
    })
];