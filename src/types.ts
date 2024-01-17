export interface RegisterChallengeResponse<B> {
	rp: {
		name: string;
		id: string;
	};
	user: {
		id: B;
		name: string;
		displayName: string;
	};
	pubKeyCredParams: [{
		type: "public-key";
		alg: -7;
	}];
	attestation: "direct",
	timeout: number;
	challenge: B;
	excludeCredentials: [];
}

export interface CredentialCreationOptions<B> {
	publicKey: RegisterChallengeResponse<B>;
}

export interface RegisterResponseRequest<B> {
	challenge: B;
	userId: B;
	type: string;
	credentialId: string;
	clientDataJSON: B;
	attestationObject: B;
}

export interface CredentialCreationResult<B> {
	response: {
		type: string;
		id: string;
		clientDataJSON: B;
		attestationObject: B;
	};
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
