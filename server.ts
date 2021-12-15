import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import express from 'express';
import helmet from 'helmet';

import cbor from 'cbor';
import coseToJwk from 'cose-to-jwk';

interface User {
	challenge?: Buffer;
	id?: string | null;
}

const cborParse = (b: Buffer): Promise<any> => {
	return new Promise((res, rej) => {
		cbor.decodeFirst(b, (error, obj) => {
			if (error != null) rej(error);
			else res(obj);
		});
	});
};

const main = () => {

	const key = fs.readFileSync('key.pem', 'utf8');
	const cert = fs.readFileSync('cert.pem', 'utf8');
	const users: User[] = fs.statSync("users.json", {throwIfNoEntry: false}) != null ? JSON.parse(fs.readFileSync("users.json", "utf8")) : [];

	const saveUsers = () => {
		fs.writeFileSync("users.json", JSON.stringify(users.map(({id}) => ({id}))), "utf8");
	};

	const httpApp = express();
	// httpApp.use(helmet());
	const webserver = https.createServer({key, cert}, httpApp);
	const root = __dirname;
	httpApp.get("/", (req, res) => { res.sendFile("index.html", {root}); });
	httpApp.get("/index.js", (req, res) => { res.sendFile("index.js", {root}); });
	const challenges = [];
	httpApp.post("/register-challenge", (req, res) => {
		const idBuffer = new Uint32Array(4);
		const i = users.length;
		idBuffer[0] = i;
		const challenge = crypto.randomBytes(32);
		users.push({challenge});
		saveUsers();
		const response = {
			rp: {
				name: "Webauthntest"
			},
			user: {
				id: Buffer.from(idBuffer).toString("base64"),
				name: `user${i}@example.com`,
				displayName: `User ${i}`
			},
			pubKeyCredParams: [{
				type: "public-key",
				alg: -7
			}],
			attestation: "direct",
			timeout: 60000,
			challenge: challenge.toString("base64"),
		};
		console.log({response});
		res.json(response);
	});
	httpApp.post("/register-response", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		console.log(req.body);

		const idBuffer = new Uint32Array(Buffer.from(req.body.user.id, "base64"));
		const userId = idBuffer[0];
		// TODO XXX: Handle uint32 overflow
		if (userId !== userId || userId < 0 || userId >= users.length) {
			res.json({"error": "Unknown or missing userId"});
			return;
		}
		if (users[userId].id != null) {
			res.json({"error": "userId already registered"});
			return;
		}

		const {authData, fmt, attStmt} = await cborParse(Buffer.from(req.body.attestationObject, "base64"));

		const rpIdHash = authData.slice(0, 32);
		// TODO XXX: Verify that rpIdHash is the sha256 hash of the hostname "localhost"
		const flagsByte = authData[32];
		const flags = {UP: flagsByte & 1, RFU1: flagsByte & 2, UV: flagsByte & 4, RFU2: flagsByte & 0x38, AT: flagsByte & 0x40, ED: flagsByte & 0x80};
		// TODO XXX: Verify that User is Present (flags.UP !== 0)
		const signCount = new Uint32Array(authData.slice(33, 37))[0];

		const cData = Buffer.from(req.body.clientDataJSON, "base64");
		const C = JSON.parse(cData.toString("utf8"));
		// TODO XXX: Verify that the value of C.type is the string webauthn.get.
		// TODO XXX: Verify that the value of C.challenge equals the base64url encoding of options.challenge.
		// TODO XXX: Verify that the value of C.origin matches the Relying Party's origin.

		// Let hash be the result of computing a hash over the cData using SHA-256.
		// Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
		console.log({authData, fmt, attStmt, flags, signCount});
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
		const credentialIdLength = new Uint16Array(authData.slice(53, 55))[0];
		if (credentialIdLength > 1023) {
			res.json({error: "Sorry, credentialIdLength is bad", credentialIdLength});
			return;
		}
		const credentialId = authData.slice(55, 55 + credentialIdLength);
		const credentialPublicKeyCose = authData.slice(55 + credentialIdLength);
		console.log({aaguid, credentialIdLength, credentialId, credentialPublicKey: credentialPublicKeyCose.toString("base64")});
		// TODO(rav): This always fails, seemingly because credentialPublicKeyCose is not valid cbor data.
		const credentialPublicKey = coseToJwk(credentialPublicKeyCose);
		console.log({credentialPublicKey});

		users[userId].id = req.body.id;
		saveUsers();
		res.json({userId: idBuffer[0]});
	});
	httpApp.post("/auth-challenge", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		console.log(req.body);
		const userId = +req.body.userId;
		if (userId !== userId || userId < 0 || userId >= users.length) {
			res.json({"error": "Unknown or missing userId"});
			return;
		}
		if (users[userId].id == null) {
			res.json({"error": "userId not registered"});
			return;
		}
		const challenge = crypto.randomBytes(32);
		const response = {
			challenge: challenge.toString("base64"),
			allowCredentials: [
				{
					id: users[userId].id,
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
		console.log(req.body);

		const authData = new Uint8Array(Buffer.from(req.body.authenticatorData, "base64"));
		const rpIdHash = authData.slice(0, 32);
		// TODO XXX: Verify that rpIdHash is the sha256 hash of the hostname "localhost"
		const flagsByte = authData[32];
		const flags = {UP: flagsByte & 1, RFU1: flagsByte & 2, UV: flagsByte & 4, RFU2: flagsByte & 0x38, AT: flagsByte & 0x40, ED: flagsByte & 0x80};
		// TODO XXX: Verify that User is Present (flags.UP !== 0)
		const signCount = new Uint32Array(authData.slice(33, 37))[0];

		const cData = Buffer.from(req.body.clientDataJSON, "base64");
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
