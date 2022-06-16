/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {Rule} from "../rule/rule.js";

/**
 * A single match within a line
 */
export interface Match {
    /**
     * Rule that was matched
     */
    readonly rule: Rule;

    /**
     * Content of the text that matched
     */
    readonly match: string;
}