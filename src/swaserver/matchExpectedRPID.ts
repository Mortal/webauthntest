import crypto from 'crypto';

const bufferEqual = (a: Buffer, b: Buffer) => {
	if (a.length !== b.length) return false;
	let ineq = 0;
	for (let i = 0; i < a.length; ++i)
		if (a[i] !== b[i])
			++ineq;
	return ineq === 0;
};

/**
 * Go through each expected RP ID and try to find one that matches. Returns the unhashed RP ID
 * that matched the hash in the response.
 */
export function matchExpectedRPID(
  rpIDHash: Buffer,
  expectedRPIDs: string[],
): string | null {
  let result: string | null = null;
  for (const expected of expectedRPIDs) {
    const expectedRPIDHash = crypto.createHash('sha256').update(expected, 'utf8').digest();
    if (bufferEqual(rpIDHash, expectedRPIDHash)) {
      result = expected;
    }
  }
  return result;
}
