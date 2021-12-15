console.log("Hello");

async function b64decode(a) {
	// console.log({a});
	return await (await fetch("data:application/octet-stream;base64," + a)).arrayBuffer();
}

function b64encode(b) {
	return new Promise((r) => {
		const blob = new Blob([b], {type:'application/octet-stream'});
		const reader = new FileReader();
		reader.onload = function(evt){
			const dataurl = evt.target.result;
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
	console.log(await b64encode(await b64decode(await b64encode(b)))[2]);
}
// test();

async function webauthntest_register() {
	console.log("Hello!");
	const serverChallenge = await (await window.fetch(
		'/register-challenge',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: "{}",
		}
	)).json();
	console.log({serverChallenge});
	const {user: {id: idB64}, challenge: challengeB64} = serverChallenge;
	const userId = new Uint32Array(await b64decode(idB64));
	document.getElementById("userid").value = userId[0];
	const challenge = await b64decode(challengeB64);
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
	});
	console.log(cred);
	const result = await (await window.fetch(
		'/register-response',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify(
				{
					...serverChallenge,
					type: cred.type,
					id: await b64encode(cred.rawId),
					clientDataJSON: await b64encode(cred.response.clientDataJSON),
					attestationObject: await b64encode(cred.response.attestationObject),
				}
			),
		}
	)).json();
	console.log({result});
}

async function webauthntest_auth() {
	console.log("Hello!");
	const serverChallenge = await (await window.fetch(
		'/auth-challenge',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify({userId: +document.getElementById("userid").value}),
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
	const cred = await navigator.credentials.get({
		publicKey: {
			allowCredentials,
			timeout: 60000,
			challenge: await b64decode(serverChallenge.challenge),
		},
	});
	console.log({cred});
	const result = await (await window.fetch(
		'/auth-response',
		{
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify(
				{
					type: cred.type,
					id: await b64encode(cred.rawId),
					clientDataJSON: await b64encode(cred.response.clientDataJSON),
					authenticatorData: await b64encode(cred.response.authenticatorData),
					signature: await b64encode(cred.response.signature),
					userHandle: await b64encode(cred.response.userHandle),
				}
			),
		}
	)).json();
	console.log({result});
}

window.addEventListener("load", () => {
	document.getElementById("register").addEventListener("click", webauthntest_register, false);
	document.getElementById("auth").addEventListener("click", webauthntest_auth, false);
}, false);
