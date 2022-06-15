/**
 * A rule to match against the input.
 */
export interface Rule {
    /** Name of the rule */
    readonly name: string;

    /** Optional description of the security issue or suspicious input */
    readonly description?: string;

    /** If this rule matches a registered CVE, then this is the CVE code (including CVE prefix) */
    readonly cve?: string;

    /** Optional array of links to more information */
    readonly links?: readonly string[];

    /** Function to check the input for matches */
    readonly match: Matcher;

    /** Optional function to decode a match */
    readonly decode?: Decoder;
}

/**
 * Check a line of input for matches.
 * Called once for each line of input.
 * @param cleaned Input string with obfuscation and encoding removed
 * @param raw Unmodified input string
 * @returns Returns iteration of regex matches. Each match should represent a separate and distinct occurrence of the rule.
 */
export type Matcher = (cleaned: string, raw: string) => (IterableIterator<RegExpMatchArray>);

/**
 * Decode a found match.
 * Called once for each match.
 * @param match Match result from the containing rule's Matcher
 * @param cleanedLine  Input string with obfuscation and encoding removed
 * @param rawLine Unmodified input string
 * @returns Returns the matched string with rule-specific decoding applied
 */
export type Decoder = (match: RegExpMatchArray, cleanedLine: string, rawLine: string) => string;