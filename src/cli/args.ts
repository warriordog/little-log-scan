/*  This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

export class Args {
    private readonly args: Map<string, Arg[]>;

    constructor(args: readonly string[]) {
        this.args = parseArgs(args);
    }

    getFlag(key: string): boolean {
        return this.args.has(key);
    }

    /**
     * Reads a "boolean" argument of the form -key=y/n.
     * Compared case-insensitively.
     * @param key Argument name
     * @param trueValue Value to treat as true. Should be lower-cased.
     * @param def Default value to return if the argument is missing.
     */
    getBool(key: string, trueValue: string, def = false): boolean {
        const value = this.args.get(key)?.at(-1)?.value;
        if (value) {
            return value.toLowerCase() === trueValue;
        } else {
            return def;
        }
    }

    getString(key: string, def?: string): string | undefined {
        // If the arg is missing at any step, then this will fall back to def.
        return this.args.get(key)?.at(-1)?.value ?? def;
    }

    getAllStrings(key: string): string[] {
        const args = this.args.get(key);
        if (!args) {
            return [];
        }

        // Ugly loop needed because .filter() won't narrow the type to remove undefined :(
        const values = [];
        for (const arg of args) {
            if (arg.value !== undefined) {
                values.push(arg.value);
            }
        }
        return values;
    }
}

export interface Arg {
    readonly key: string;
    readonly value?: string;
}

function parseArgs(argStrings: readonly string[]): Map<string, Arg[]> {
    const args: Map<string, Arg[]> = new Map();

    for (const argStr of argStrings) {
        const split = argStr.indexOf('=');
        if (split > 0) {
            const key = argStr.substring(0, split).toLowerCase();
            if (split < argStr.length - 1) {
                const value = argStr.substring(split + 1);
                // Key + value
                addArg({ key, value }, args);
            } else {
                // Key + empty value
                addArg({ key, value: '' }, args);
            }
        } else {
            // Key only
            addArg({ key: argStr.toLowerCase() }, args);
        }
    }

    return args;
}

function addArg(arg: Arg, args: Map<string, Arg[]>): void {
    // Find the correct array for this arg
    let argArr = args.get(arg.key);

    // Create it if missing
    if (!argArr) {
        argArr = [];
        args.set(arg.key, argArr);
    }

    // Add to the array
    argArr.push(arg);
}