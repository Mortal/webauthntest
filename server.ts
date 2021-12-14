import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import express from 'express';
import helmet from 'helmet';

const main = () => {

	const key = fs.readFileSync('key.pem', 'utf8');
	const cert = fs.readFileSync('cert.pem', 'utf8');

	const httpApp = express();
	// httpApp.use(helmet());
	const webserver = https.createServer({key, cert}, httpApp);
	const root = __dirname;
	httpApp.get("/", (req, res) => { res.sendFile("index.html", {root}); });
	httpApp.get("/index.js", (req, res) => { res.sendFile("index.js", {root}); });
	const challenges = [];
	const ids: (number | null)[] = [];
	httpApp.post("/register-challenge", (req, res) => {
		const idBuffer = new Uint32Array(4);
		const i = challenges.length;
		idBuffer[0] = i;
		const challenge = crypto.randomBytes(32);
		challenges.push(challenge);
		ids.push(null);
		res.json(
			{
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
			}
		);
	});
	httpApp.post("/register-response", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		console.log(req.body);
		const idBuffer = new Uint32Array(Buffer.from(req.body.user.id, "base64"));
		ids[idBuffer[0]] = req.body.id;
		res.json({userId: idBuffer[0]});
	});
	httpApp.post("/auth-challenge", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		console.log(req.body);
		const userId = +req.body.userId;
		if (userId !== userId || userId < 0 || userId >= challenges.length) {
			res.json({"error": "Unknown or missing userId"});
			return;
		}
		if (ids[userId] == null) {
			res.json({"error": "userId not registered"});
			return;
		}
		const challenge = crypto.randomBytes(32);
		res.json(
			{
				challenge: challenge.toString("base64"),
				allowCredentials: [
					{
						id: ids[userId],
						transports: ["usb", "nfc", "ble"],
						type: "public-key",
					}
				],
				timeout: 60000,
			}
		);
	});
	httpApp.post("/auth-response", async (req, res) => {
		await new Promise((n) => express.json()(req, res, n));
		console.log(req.body);
		res.json({bar:true});
	});
	const port = 4433;
	webserver.listen(port, "localhost", () => {
		console.log(`Listening on https://localhost:${port}`);
        });
};

main();
