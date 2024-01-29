/**
 * A collection of methods for isomorphic manipulation of trickier data types
 *
 * The goal with these is to make it easier to replace dependencies later that might not play well
 * with specific server-like runtimes that expose global Web APIs (CloudFlare Workers, Deno, Bun,
 * etc...), while also supporting execution in Node.
 */
export * as isoCBOR from './isoCBOR.ts';
