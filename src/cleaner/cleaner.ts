/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

export interface Cleaner {
    /**
     * Cleans and decodes as much of the provided line as possible.
     * If the line cannot be cleaned, then it should be returned as-is.
     * This may be called multiple times as the line is progressively cleaned by multiple iterations.
     * @param line Line to process
     */
    (line: string): string;
}

