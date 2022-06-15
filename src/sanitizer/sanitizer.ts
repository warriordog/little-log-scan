/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

export interface Sanitizer {
    /**
     * Sanitizes a block of text so that it is safe to output.
     * Non-printable and special characters should be removed.
     * @param data Text to sanitize
     */
    (data: string): string;
}