import './style.css';
import { b64urlencode, b64urldecode } from './shared';
import type * as types from './types';

async function b64decode(a: string): Promise<ArrayBuffer> {
	return await (await fetch("data:application/octet-stream;base64," + a)).arrayBuffer();
}

function b64encode(b: Uint32Array | ArrayBuffer): Promise<string> {
	return new Promise((r) => {
		const blob = new Blob([b], {type:'application/octet-stream'});
		const reader = new FileReader();
		reader.onload = function(evt){
			if (evt.target == null) return;
			const dataurl = evt.target.result;
			if (typeof dataurl !== "string") return;
			// console.log(dataurl.substring(0, 100));
			const i = dataurl.indexOf(',');
			const typ = dataurl.substring(0, i);
			if (typ !== "data:application/octet-stream;base64") {
				console.log("base64 encoding failure - unknown data-URI type:", {typ});
			}
			r(dataurl.substring(i + 1));
		};
		reader.readAsDataURL(blob);
	});
}

async function test() {
	const b = new Uint32Array(4);
	b[0] = 1;
	b[1] = 2;
	b[2] = 3;
	b[3] = 4;
	console.log(await b64encode(b));
	console.log(new Uint32Array(await b64decode(await b64encode(b)))[2]);
	//console.log(await b64encode(await b64decode(await b64encode(b)))[2]);
}
// test();

async function webauthntest_register() {
	const serverChallenge: types.RegisterChallengeResponse<string> = await (await window.fetch(
		'/rp/register-challenge',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: "{}",
		}
	)).json();
	console.log({serverChallenge});
	const {user: {id: idB64}, challenge: challengeB64} = serverChallenge;
	const userId = await b64decode(b64urldecode(idB64));
	const userIdElement = document.getElementById("userid") as HTMLInputElement | null;
	if (userIdElement == null) return;
	userIdElement.value = b64urlencode(await b64encode(userId));
	const challenge = await b64decode(b64urldecode(challengeB64));
	console.log(challenge);
	const cred = await navigator.credentials.create({
		publicKey: {
			...serverChallenge,
			user: {
				...serverChallenge.user,
				id: userId,
			},
			challenge,
		},
	}) as PublicKeyCredential | null;
	if (cred == null) return;
	console.log(cred);
	const credResponse = cred.response as AuthenticatorAttestationResponse;
	const registerResponseRequest: types.RegisterResponseRequest<string> = {
		challenge: b64urlencode(await b64encode(challenge)),
		userId: b64urlencode(await b64encode(userId)),
		type: cred.type,
		credentialId: cred.id,
		clientDataJSON: b64urlencode(await b64encode(credResponse.clientDataJSON)),
		attestationObject: b64urlencode(await b64encode(credResponse.attestationObject)),
	}
	const result = await (await window.fetch(
		'/rp/register-response',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify(registerResponseRequest),
		}
	)).json();
	console.log({result});
}

async function webauthntest_auth() {
	console.log("Hello!");
	const userIdElement = document.getElementById("userid") as HTMLInputElement | null;
	if (userIdElement == null) return;
	const serverChallenge: types.AuthChallengeResponse = await (await window.fetch(
		'/rp/auth-challenge',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify({userId: userIdElement.value}),
		}
	)).json();
	console.log({serverChallenge});
	const challenge = await b64decode(serverChallenge.challenge);
	console.log(challenge);
	const allowCredentials = [];
	for (const {id, transports, type} of serverChallenge.allowCredentials) {
		console.log({id});
		allowCredentials.push({
			id: await b64decode(id),
			transports,
			type,
		});
	}
	const cred = (await navigator.credentials.get({
		publicKey: {
			allowCredentials,
			timeout: 60000,
			challenge: await b64decode(serverChallenge.challenge),
		},
	})) as PublicKeyCredential | null;
	if (cred == null) return;
	console.log({cred});
	const credResponse = cred.response as AuthenticatorAssertionResponse;
	if (credResponse == null) return;
	const userHandle = credResponse.userHandle;
	const authResponseRequest: types.AuthResponseRequest = {
		userId: userIdElement.value,
		challenge: serverChallenge.challenge,
		type: cred.type,
		id: await b64encode(cred.rawId),
		clientDataJSON: await b64encode(credResponse.clientDataJSON),
		authenticatorData: await b64encode(credResponse.authenticatorData),
		signature: await b64encode(credResponse.signature),
		userHandle: userHandle == null ? null : await b64encode(userHandle),
	};
	const result = await (await window.fetch(
		'/rp/auth-response',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify(authResponseRequest),
		}
	)).json();
	console.log({result});
}

console.log("Hello");
const registerElement = document.getElementById("register");
const authElement = document.getElementById("auth");
if (registerElement) registerElement.addEventListener("click", webauthntest_register, false);
if (authElement) authElement.addEventListener("click", webauthntest_auth, false);
