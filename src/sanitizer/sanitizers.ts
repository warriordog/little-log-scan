/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Sanitizer} from "./sanitizer.js";

const escapes: Record<string, string | undefined> = {
    '\x00': '\\0',
    '\x09': '\\t',
    '\x0A': '\\n',
    '\x0D': '\\r',
};

export const allSanitizers: readonly Sanitizer[] = [
    // Escape special characters
    // From https://stackoverflow.com/a/24231346
    string => string.replace(/[^ -~]/g, match => escapes[match] || `\\u{${match.charCodeAt(0).toString(16).toUpperCase()}}`)
];