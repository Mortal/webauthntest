export interface RegisterChallengeResponse {
	rp: {name: string};
	user: {
		id: string;
		name: string;
		displayName: string;
	};
	pubKeyCredParams: [{
		type: "public-key";
		alg: -7;
	}];
	attestation: "direct",
	timeout: number;
	challenge: string;
}

export interface RegisterResponseRequest {
	challenge: string;
	userId: string;
	type: string;
	credentialId: string;
	clientDataJSON: string;
	attestationObject: string;
}

export interface AuthChallengeResponse {
	challenge: string;
	allowCredentials: [{
		id: string;
		transports: AuthenticatorTransport[];
		type: "public-key";
	}];
	timeout: number;
}

export interface AuthResponseRequest {
	challenge: string;
	userId: string;

	type: string;
	id: string;
	clientDataJSON: string;
	authenticatorData: string;
	signature: string;
	userHandle: string | null;
}
