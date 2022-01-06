import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import express from 'express';
import helmet from 'helmet';

import cbor from 'cbor';
import coseToJwk from 'cose-to-jwk';

import { b64urlencode, b64urldecode } from './shared';
import * as types from './types';

const subtle = (crypto.webcrypto as any).subtle;

interface User {
	challenge?: string;
	id?: string | null;
	userId: string;
}

const cborParse = (b: Buffer): Promise<any> => {
	return new Promise((res, rej) => {
		cbor.decodeFirst(b, (error, obj) => {
			if (error != null) rej(error);
			else res(obj);
		});
	});
};

const bufferEqual = (a: Buffer, b: Buffer) => {
	if (a.length !== b.length) return false;
	let ineq = 0;
	for (let i = 0; i < a.length; ++i)
		if (a[i] !== b[i])
			++ineq;
	return ineq === 0;
};

const main = () => {

	const key = fs.readFileSync('key.pem', 'utf8');
	const cert = fs.readFileSync('cert.pem', 'utf8');
	const users: User[] = fs.statSync("users.json", {throwIfNoEntry: false}) != null ? JSON.parse(fs.readFileSync("users.json", "utf8")) : [];
	const usersById: {[userId: string]: User} = {};
	for (const user of users)
		usersById[user.userId] = user;

	const saveUsers = () => {
		fs.writeFileSync("users.json", JSON.stringify(users.map(({id, userId}) => ({id, userId}))), "utf8");
	};

	const httpApp = express();
	// httpApp.use(helmet());
	const webserver = https.createServer({key, cert}, httpApp);
	const root = __dirname;
	httpApp.get("/", (req, res) => { res.sendFile("index.html", {root}); });
	httpApp.get("/index.js", (req, res) => { res.sendFile("index.js", {root}); });
	const challenges = [];
	httpApp.post("/register-challenge", (req, res) => {
		const i = users.length;
		const userId = b64urlencode(crypto.randomBytes(32).toString("base64"));
		const challenge = b64urlencode(crypto.randomBytes(32).toString("base64"));
		const user = {userId, challenge};
		users.push(user);
		usersById[user.userId] = user;
		saveUsers();
		const response: types.RegisterChallengeResponse = {
			rp: {
				name: "Webauthntest"
			},
			user: {
				id: userId,
				name: `user${i}@example.com`,
				displayName: `User ${i}`
			},
			pubKeyCredParams: [{
				type: "public-key",
				alg: -7
			}],
			attestation: "direct",
			timeout: 60000,
			challenge,
		};
		console.log({response});
		res.json(response);
	});
	httpApp.post("/register-response", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		const body: types.RegisterResponseRequest = req.body;
		console.log(body);
		const userId = Buffer.from(b64urldecode(body.userId), "base64");
		const userIdB64 = b64urlencode(userId.toString("base64"));
		const user = usersById[userIdB64];
		if (user == null) {
			res.json({"error": "Unknown or missing userId"});
			return;
		}
		if (user.id != null || user.challenge == null) {
			res.json({"error": "userId already registered"});
			return;
		}

		const {authData, fmt, attStmt} = await cborParse(Buffer.from(body.attestationObject, "base64"));

		const rpIdHash = authData.slice(0, 32);
		const hostname = "localhost";
		const origin = `https://${hostname}:4433`;
		const hostnameHash = crypto.createHash('sha256').update(hostname, 'utf8').digest();
		if (!bufferEqual(hostnameHash, rpIdHash)) {
			res.json({"error": "wrong rpIdHash"});
			return;
		}
		const flagsByte = authData[32];
		const flags = {UP: flagsByte & 1, RFU1: flagsByte & 2, UV: flagsByte & 4, RFU2: flagsByte & 0x38, AT: flagsByte & 0x40, ED: flagsByte & 0x80};
		if (!flags.UP) {
			res.json({"error": "UP not set"});
			return;
		}
		const signCount = new Uint32Array(authData.slice(33, 37))[0];

		const cData = Buffer.from(body.clientDataJSON, "base64");
		const C = JSON.parse(cData.toString("utf8"));
		if (C.origin !== origin || C.type !== "webauthn.create" || C.challenge !== user.challenge || C.hashAlgorithm !== "SHA-256") {
			res.json({"error": "Unexpected origin/type/challenge/hashAlgorithm", expected: {origin, type: "webauthn.create", challenge: user.challenge, hashAlgorithm: "SHA-256"}, got: C});
			return;
		}
		const cDataHash = crypto.createHash('sha256').update(cData).digest();

		// Let hash be the result of computing a hash over the cData using SHA-256.
		// Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
		console.log({C, authData: authData.toString("base64"), fmt, attStmt, flags, signCount});
		if (fmt !== "fido-u2f") {
			res.json({error: "Sorry, your format is not implemented", fmt});
			return;
		}
		const {x5c: [attCert, ...chain], sig} = attStmt;
		if (chain.length > 0) {
			res.json({error: "Sorry, we don't validate certificate chains here"});
			return;
		}
		console.log({attCert, sig});

		const aaguid = authData.slice(37, 53);
		const credentialIdLength = authData.readUInt16BE(53);
		console.log({credentialIdLength, bla: authData.slice(53, 55)});
		if (credentialIdLength > 1023) {
			res.json({error: "Sorry, credentialIdLength is bad", credentialIdLength});
			return;
		}
		const credentialId = authData.slice(55, 55 + credentialIdLength);
		const credentialPublicKeyCose = authData.slice(55 + credentialIdLength);
		console.log({aaguid, credentialIdLength, credentialId, credentialPublicKey: credentialPublicKeyCose.toString("base64")});
		const credentialPublicKey = coseToJwk(credentialPublicKeyCose);
		console.log({credentialPublicKey});

		const importedKey = await subtle.importKey("jwk", {...credentialPublicKey, alg: undefined}, {name: "ECDSA", namedCurve: "P-256"}, true, ["verify"]);
		console.log({importedKey});
		const verifyResult = await subtle.verify(
			{
				name: "ECDSA",
				hash: "SHA-256",
			},
			importedKey,
			sig,
			Buffer.concat([authData, cDataHash])
		);
		if (!verifyResult) {
			res.json({"error": "Failed to verify that sig is a valid signature over the binary concatenation of authData and hash."});
			return;
		}

		// TODO: Store credentialPublicKey and use it later
		// TODO: Require an auth-challenge before actually storing the key

		user.id = body.credentialId;
		saveUsers();
		res.json({userId: userIdB64});
	});
	httpApp.post("/auth-challenge", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		console.log(req.body);
		const userId = req.body.userId;
		if (userId !== userId || userId < 0 || userId >= users.length) {
			res.json({"error": "Unknown or missing userId"});
			return;
		}
		const id = users[userId].id;
		if (id == null) {
			res.json({"error": "userId not registered"});
			return;
		}
		const challenge = crypto.randomBytes(32);
		const response: types.AuthChallengeResponse = {
			challenge: challenge.toString("base64"),
			allowCredentials: [
				{
					id: id,
					transports: ["usb", "nfc", "ble"],
					type: "public-key",
				}
			],
			timeout: 60000,
		};
		console.log({response});
		console.log(response.allowCredentials[0]);
		res.json(response);
	});
	httpApp.post("/auth-response", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		const body: types.AuthResponseRequest = req.body;
		console.log(body);

		const authData = new Uint8Array(Buffer.from(body.authenticatorData, "base64"));
		const rpIdHash = authData.slice(0, 32);
		// TODO XXX: Verify that rpIdHash is the sha256 hash of the hostname "localhost"
		const flagsByte = authData[32];
		const flags = {UP: flagsByte & 1, RFU1: flagsByte & 2, UV: flagsByte & 4, RFU2: flagsByte & 0x38, AT: flagsByte & 0x40, ED: flagsByte & 0x80};
		// TODO XXX: Verify that User is Present (flags.UP !== 0)
		const signCount = new Uint32Array(authData.slice(33, 37))[0];

		const cData = Buffer.from(body.clientDataJSON, "base64");
		const C = JSON.parse(cData.toString("utf8"));
		// TODO XXX: Verify that the value of C.type is the string webauthn.get.
		// TODO XXX: Verify that the value of C.challenge equals the base64url encoding of options.challenge.
		// TODO XXX: Verify that the value of C.origin matches the Relying Party's origin.

		// Let hash be the result of computing a hash over the cData using SHA-256.
		// Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
		console.log({flags, signCount, C});
		res.json({bar:true});
	});
	const port = 4433;
	webserver.listen(port, "localhost", () => {
		console.log(`Listening on https://localhost:${port}`);
        });
};

main();
