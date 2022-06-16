/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Match} from "./match.js";

/**
 * A set of matches originating from a single line
 */
export interface MatchInfo {
    /**
     * Line index, measured by number of lines read.
     */
    readonly lineNumber: number;

    /**
     * Decoded (but NOT sanitized) content of the line
     */
    readonly cleanedLine: string;

    /** Raw (unchanged and NOT sanitized) content of the line */
    readonly rawLine: string;

    /**
     * Array of matches in the line
     */
    readonly matches: Match[];
}