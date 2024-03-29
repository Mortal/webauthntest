import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import express from 'express';
// import helmet from 'helmet';

// import * as asn1js from 'asn1js';

// import cbor from 'cbor';
// import coseToJwk from 'cose-to-jwk';

import { b64urlencode, b64urldecode } from './shared.ts';
import * as types from './types.ts';

import { AuthenticationResponseJSON, PublicKeyCredentialRequestOptionsJSON } from './swatypes/index.ts';
import { VerifyAuthenticationResponseOpts, verifyAuthenticationResponse } from './swaserver/verifyAuthenticationResponse.ts';
import { VerifyRegistrationResponseOpts, verifyRegistrationResponse } from './swaserver/verifyRegistrationResponse.ts';

// const subtle = crypto.subtle;

type User = {
	credentialPublicKey: string;
	credentialID: string;
	counter: number;
	transports: VerifyRegistrationResponseOpts["response"]["response"]["transports"] & {};
};

// type User = VerifiedRegistrationResponse["registrationInfo"] & {};
// interface User {
// 	credentialId: string;
// 	credentialPublicKey: {
// 		kty: 'EC';
// 		alg: 'ECDSA_w_SHA256';
// 		crv: 'P-256';
// 		x: string;
// 		y: string;
// 	};
// }

// const cborParse = (b: Buffer): Promise<any> => {
// 	return new Promise((res, rej) => {
// 		cbor.decodeFirst(b, (error, obj) => {
// 			if (error != null) rej(error);
// 			else res(obj);
// 		});
// 	});
// };

// const bufferEqual = (a: Buffer, b: Buffer) => {
// 	if (a.length !== b.length) return false;
// 	let ineq = 0;
// 	for (let i = 0; i < a.length; ++i)
// 		if (a[i] !== b[i])
// 			++ineq;
// 	return ineq === 0;
// };

const main = () => {

	const httpApp = express();
	// httpApp.use(helmet());
	// const root = __dirname;
	httpApp.use("/rp", routeRp());
	httpApp.use("/credentials", routeCredentials());
	// httpApp.get("/", (_req, res) => { res.sendFile("index.html", {root}); });
	// httpApp.get("/index.js", (_req, res) => { res.sendFile("index.js", {root}); });

	const key = fs.readFileSync('key.pem', 'utf8');
	const cert = fs.readFileSync('cert.pem', 'utf8');

	const webserver = https.createServer({ key, cert }, httpApp);
	const port = 4433;
	webserver.listen(port, "localhost", () => {
		console.log(`Listening on https://localhost:${port}`);
	});
};

const routeRp = () => {
	const router = express.Router();

	// const hostname = "localhost";
	// const origins = [`https://${hostname}:4433`, `https://${hostname}:5173`];
	// const hostnameHash = crypto.createHash('sha256').update(hostname, 'utf8').digest();

	const users: { [userId: string]: User } = fs.statSync("users.json", { throwIfNoEntry: false }) != null ? JSON.parse(fs.readFileSync("users.json", "utf8")) : {};

	const saveUsers = () => {
		console.log({ users });
		fs.writeFileSync("users.json", JSON.stringify(users), "utf8");
	};

	const registerChallenges: { [userId: string]: string } = {};

	router.route("/register-challenge").post(async (_req, res) => {
		const i = Object.keys(users).length;
		const userId = b64urlencode(crypto.randomBytes(32).toString("base64"));
		const rpName = "Webauthntest";
		const rpID = "localhost";
		const userID = userId;
		const userName = `user${i}@example.com`;
		const timeout = 60000;
		const attestationType = 'direct';
		const supportedAlgorithmIDs = [-7];
		// const extensions = undefined; 
		// const extensions = {
		// 	credProps: true,
		// 	hmacCreateSecret: false
		// }
		const challenge = b64urlencode(crypto.randomBytes(32).toString("base64"));
		const userDisplayName = userName;
		const defaultAuthenticatorSelection = {
			residentKey: 'preferred',
			userVerification: 'preferred',
		};
		const authenticatorSelection = {
			...defaultAuthenticatorSelection,
			requireResidentKey: false,
		};
		// const response = await generateRegistrationOptions(opts);
		const pubKeyCredParams = supportedAlgorithmIDs.map((id) => ({
			alg: id,
			type: 'public-key',
		}));
		const response = {
			challenge,
			rp: {
				name: rpName,
				id: rpID,
			},
			user: {
				id: userID,
				name: userName,
				displayName: userDisplayName,
			},
			pubKeyCredParams,
			timeout,
			attestation: attestationType,
			authenticatorSelection,
			extensions: {
				credProps: true,
			},
		};

		registerChallenges[userId] = challenge;
		saveUsers();
		// const response: types.RegisterChallengeResponse<string> = {
		// 	rp: {
		// 		name: "Webauthntest",
		// 		id: "localhost",
		// 	},
		// 	user: {
		// 		id: userId,
		// 		name: `user${i}@example.com`,
		// 		displayName: `User ${i}`
		// 	},
		// 	pubKeyCredParams: [{
		// 		type: "public-key",
		// 		alg: -7
		// 	}],
		// 	attestation: "direct",
		// 	timeout: 60000,
		// 	challenge,
		// };
		console.log({ response });
		res.json(response);
	});

	router.route("/register-response").post(express.json(), async (req, res) => {
		const { response: attResponse, userId: userIdB64 } = req.body as { response: VerifyRegistrationResponseOpts["response"], userId: string };
		console.log(attResponse);
		// const userId = Buffer.from(b64urldecode(attResponse.id), "base64");
		// const userIdB64 = b64urlencode(userId.toString("base64"));
		const expectedChallenge = registerChallenges[userIdB64];
		if (expectedChallenge == null) {
			res.json({ "error": "Unknown or missing userId" });
			return;
		}
		delete registerChallenges[userIdB64];

		const opts: VerifyRegistrationResponseOpts = {
			response: attResponse,
			expectedChallenge: [`${expectedChallenge}`],
			expectedOrigin: ["https://localhost:5173", "https://localhost:4433"],  // or 4433?
			expectedRPID: ["localhost"],
			supportedAlgorithmIDs: [-7]
		};
		const verification = await verifyRegistrationResponse(opts);

		const { verified: verifyResult, registrationInfo } = verification;

		// const {authData, fmt, attStmt} = await cborParse(Buffer.from(attResponse.attestationObject, "base64"));

		// const rpIdHash: Buffer = authData.slice(0, 32);
		// if (!bufferEqual(hostnameHash, rpIdHash)) {
		// 	res.json({"error": "wrong rpIdHash"});
		// 	return;
		// }
		// const flagsByte = authData[32];
		// const flags = {UP: flagsByte & 1, RFU1: flagsByte & 2, UV: flagsByte & 4, RFU2: flagsByte & 0x38, AT: flagsByte & 0x40, ED: flagsByte & 0x80};
		// if (!flags.UP) {
		// 	res.json({"error": "UP not set"});
		// 	return;
		// }
		// const signCount = authData.readUInt32BE(33);

		// const cData = Buffer.from(attResponse.clientDataJSON, "base64");
		// const C = JSON.parse(cData.toString("utf8"));
		// console.log({cData: cData.toString("utf8"), C});
		// if (!origins.includes(C.origin) || C.type !== "webauthn.create" || C.challenge !== expectedChallenge || !["SHA-256", undefined].includes(C.hashAlgorithm)) {
		// 	res.json({"error": "Unexpected origin/type/challenge/hashAlgorithm", expected: {origins, type: "webauthn.create", challenge: expectedChallenge, hashAlgorithm: "SHA-256"}, got: C});
		// 	return;
		// }
		// const cDataHash: Buffer = crypto.createHash('sha256').update(cData).digest();
		// console.log({cDataHash})

		// console.log({C, authData: authData.toString("base64"), fmt, attStmt, flags, signCount});
		// if (fmt !== "fido-u2f") {
		// 	res.json({error: "Sorry, your format is not implemented", fmt});
		// 	return;
		// }
		// const {x5c: [attCert, ...chain], sig} = attStmt;
		// if (chain.length > 0) {
		// 	res.json({error: "Sorry, we don't validate certificate chains here"});
		// 	return;
		// }
		// console.log({attCert: attCert.toString("base64"), sig});
		// // TODO: Let certificate public key be the public key conveyed by attCert. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
		// // https://w3c.github.io/webauthn/

		// const aaguid = authData.slice(37, 53);
		// const credentialIdLength = authData.readUInt16BE(53);
		// console.log({credentialIdLength, bla: authData.slice(53, 55)});
		// if (credentialIdLength > 1023) {
		// 	res.json({error: "Sorry, credentialIdLength is bad", credentialIdLength});
		// 	return;
		// }
		// const credentialId: Buffer = authData.slice(55, 55 + credentialIdLength);
		// const credentialPublicKeyCose = authData.slice(55 + credentialIdLength);
		// console.log({aaguid, credentialIdLength, credentialId, credentialPublicKey: credentialPublicKeyCose.toString("base64")});
		// // Parse COSE key. First nibble should be 0xa, for a small CBOR map.
		// const credentialPublicKey = coseToJwk(credentialPublicKeyCose);
		// console.log({credentialPublicKey});

		// const jwk = {
		// 	kty: "EC",
		// 	crv: "P-256",
		// 	alg: "ES256", // credentialPublicKey.alg,
		// 	// key_ops: ["sign", "verify"],
		// 	x: b64urlencode(credentialPublicKey.x),
		// 	y: b64urlencode(credentialPublicKey.y),
		// };
		// console.log({jwk});
		// const importedKey = await subtle.importKey("jwk", jwk, {name: "ECDSA", namedCurve: "P-256", hash: "SHA-256"}, true, ["verify"]);

		// // Construct an X9.62 key (65 bytes long)
		// const publicKeyU2F: Buffer = Buffer.concat([
		// 	Buffer.from([0x04]),
		// 	Buffer.from(credentialPublicKey.x, "base64"),
		// 	Buffer.from(credentialPublicKey.y, "base64"),
		// ]);
		// const verificationData = Buffer.concat([
		// 	Buffer.from([0x00]),
		// 	rpIdHash,
		// 	cDataHash,
		// 	credentialId,
		// 	publicKeyU2F,
		// ]);
		// console.log({
		// 	lengths: {
		// 		sig: sig.length,
		// 		rpIdHash: rpIdHash.length,
		// 		cDataHash: cDataHash.length,
		// 		credentialId: credentialId.length,
		// 		publicKeyU2F: publicKeyU2F.length,
		// 		verificationData: verificationData.length,
		// 		expected: 1 + 32 + 32 + credentialId.length + 65,
		// 	},
		// });
		// // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
		// // Verify the sig using verificationData and the certificate public key per section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
		// console.log({credentialPublicKey, importedKey, publicKeyU2F: publicKeyU2F.toString("base64"), verificationData: verificationData.toString("base64"), sig: sig.toString("base64")});

		// // const fixedBuffer = (buf: ArrayBuffer, n: number) => {
		// // 	console.log("fixedBuffer", {n, l: buf.byteLength})
		// // 	return Buffer.concat([
		// // 		Buffer.from(new Array(n - buf.byteLength).fill(0)),
		// // 		Buffer.from(buf),
		// // 	])
		// // };

		// // const asn1SigToRaw = (sig: Buffer): Buffer => {
		// // 	const ber = asn1js.fromBER(new Uint8Array(sig).buffer);
		// // 	const r: asn1js.Sequence = ber.result as any;
		// // 	const ints: asn1js.Integer[] = r.valueBlock.value as any;

		// // 	return Buffer.concat([
		// // 		fixedBuffer(ints[0].valueBlock.valueHex, 32),
		// // 		fixedBuffer(ints[1].valueBlock.valueHex, 32),
		// // 	]);
		// // };

		// const fixedBuffer2 = (b: Buffer, n: number): Buffer => {
		// 	console.log("fixedBuffer2", {n, l: b.length})
		// 	return Buffer.concat([Buffer.from(new Array(n).fill(0)), b]).slice(b.length);
		// }

		// const asn1SigToRaw2 = (sig: Buffer): Buffer => {
		// 	// https://github.com/webauthn-open-source/fido2-lib/blob/89be15ab538ec0cbc557527c007ffa1c8729de7c/lib/toolbox.js#L71
		// 	const rStart = 4;
		// 	const rEnd = rStart + sig.readUInt8(3)
		// 	const sStart = rEnd + 2;
		// 	const r = fixedBuffer2(sig.slice(rStart, rEnd), 32);
		// 	const s = fixedBuffer2(sig.slice(sStart), 32);
		// 	return Buffer.concat([r, s]);
		// };

		// // const sig2 = asn1SigToRaw(sig);
		// const sig2 = asn1SigToRaw2(sig);

		// const myKey = await subtle.generateKey({name: "ECDSA", namedCurve: "P-256", hash: "SHA-256"}, true, ["verify", "sign"]);
		// console.log({myKey});
		// const mySig = await subtle.sign(
		// 	{
		// 		name: "ECDSA",
		// 		hash: {name: "SHA-256"},
		// 	},
		// 	myKey.privateKey,
		// 	verificationData
		// );
		// const myResult = await subtle.verify(
		// 	{
		// 		name: "ECDSA",
		// 		hash: {name: "SHA-256"},
		// 	},
		// 	myKey.publicKey,
		// 	Buffer.from(mySig),
		// 	verificationData
		// );
		// console.log({myResult, mySig: Buffer.from(mySig).toString("base64"), sig: sig.toString("base64"), sig2: sig2.toString("base64")});

		// // Verify the ASN.1 signature "sig"
		// const verifyResult = await subtle.verify(
		// 	{
		// 		name: "ECDSA",
		// 		hash: {name: "SHA-256"},
		// 	},
		// 	importedKey,
		// 	sig2,
		// 	new Uint8Array(verificationData)
		// );
		if (!verifyResult) {
			console.log("Verify failed");
			res.json({ "error": "Failed to verify that sig is a valid signature over the binary concatenation of authData and hash." });
			return;
		}
		if (!registrationInfo) {
			throw new Error("verified, but no registrationInfo?");
		}
		const { credentialPublicKey, credentialID, counter } = registrationInfo;

		// users[userIdB64] = {
		// 	credentialId: attResponse.credentialId,
		// 	credentialPublicKey: credentialPublicKey as any,
		// };
		users[userIdB64] = {
			credentialPublicKey: b64urlencode(Buffer.from(credentialPublicKey).toString("base64")),
			credentialID: b64urlencode(Buffer.from(credentialID).toString("base64")),
			counter,
			transports: attResponse.response.transports || []
		};
		saveUsers();
		res.json({ userId: userIdB64 });
	});

	const authChallenges: { [challenge: string]: string } = {};

	router.route("/auth-challenge").post(express.json(), async (req, res) => {
		console.log(req.body);
		const userId = req.body.userId;
		const user = users[userId];
		if (user == null) {
			res.json({ "error": "Unknown or missing userId" });
			return;
		}
		// const credentialId: string = b64urlencode(Buffer.from(user.credentialID).toString("base64"));
		const challenge = b64urlencode(crypto.randomBytes(32).toString("base64"));
		const response: PublicKeyCredentialRequestOptionsJSON = {
			challenge,
			allowCredentials: [user].map(authenticator => ({
				id: authenticator.credentialID,
				type: 'public-key',
				transports: authenticator.transports,
			})),
			timeout: 60000,
			userVerification: "discouraged",
			// extensions: {
			//     credProps: true,
			//     hmacCreateSecret: false
			// }
			rpId: "localhost",
		};

		authChallenges[challenge] = userId;
		// const response: types.AuthChallengeResponse = {
		// 	challenge,
		// 	allowCredentials: [
		// 		{
		// 			id: credentialId,
		// 			transports: ["usb", "nfc", "ble"],
		// 			type: "public-key",
		// 		}
		// 	],
		// 	timeout: 60000,
		// };
		// console.log({response});
		// console.log(response.allowCredentials[0]);
		res.json(response);
	});

	router.route("/auth-response").post(express.json(), async (req, res) => {
		console.log(req.body);
		const { userId, challenge, response } = req.body as { userId: string, challenge: string, response: AuthenticationResponseJSON };
		console.log(response);
		if (authChallenges[challenge] !== userId) {
			console.log({ response, expected: authChallenges[challenge], challenge, authChallenges });
			res.json({ "error": "Unknown challenge" });
			return;
		}
		const user = users[userId];
		if (user == null) {
			res.json({ "error": "Unknown user" });
			return;
		}
		delete authChallenges[challenge];
		if (user.credentialID !== response.id) {
			res.json({ "error": "Wrong credential id" });
			return;
		}
		const thisDevice = {
			credentialPublicKey: Buffer.from(b64urldecode(user.credentialPublicKey), "base64"),
			credentialID: Buffer.from(b64urldecode(user.credentialID), "base64"),
			counter: user.counter,
			transports: user.transports || [],
		};
		const opts: VerifyAuthenticationResponseOpts = {
			response,
			expectedChallenge: challenge,
			expectedOrigin: ["https://localhost:5173", "https://localhost:4433"],
			expectedRPID: ["localhost"],
			authenticator: thisDevice,
		};
		const verification = await verifyAuthenticationResponse(opts);
		const { verified, authenticationInfo } = verification;

		if (!verified) {
			res.json({ error: "Not verified" });
			return;
		}
		if (!authenticationInfo) {
			throw new Error("verified, but no authenticationInfo");
		}
		res.json({ success: true });
	});
	return router;
};

const routeCredentials = () => {
	const router = express.Router();

	router.route("/create")
		.post(express.json(), async (req, res) => {
			const body: types.CredentialCreationOptions<string> = req.body;
			const { publicKey } = body;
			const result: types.CredentialCreationResult<string> = {
				response: {
					id: publicKey.user.id,
					attestationObject: "some cbor object...",
					clientDataJSON: b64urlencode(Buffer.from(JSON.stringify({
						origin: "https://localhost:4433",
						type: "webauthn.create",
						challenge: publicKey.challenge,
						hashAlgorithm: "SHA-256",
					})).toString("base64")),
					type: "foo",
				},
			};
			res.json(result);
		});

	return router;
};

main();
