import argparse
import base64
from typing import TypedDict

import requests
from fido2.webauthn import PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor, UserVerificationRequirement, AuthenticatorTransport, PublicKeyCredentialType
from fido2.client import Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice


class AuthChallengeAllowCredentialsJson(TypedDict):
    id: str
    type: str
    transports: list[str]


class AuthChallengeJson(TypedDict):
    challenge: str
    allowCredentials: list[AuthChallengeAllowCredentialsJson]
    timeout: int
    userVerification: str
    rpId: str


parser = argparse.ArgumentParser()
parser.add_argument("userid")


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return input("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def unpadded_urlsafe_b64decode(s: str) -> bytes:
    n = -len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * n)


def unpadded_urlsafe_b64encode(s: bytes) -> str:
    return base64.urlsafe_b64encode(s).decode().rstrip("=")


def main() -> None:
    args = parser.parse_args()
    r: AuthChallengeJson = requests.post("https://localhost:5173/rp/auth-challenge", json={"userId": args.userid}, verify=False).json()
    print(r)
    {'challenge': '00MhzgbbYf_FPxX15dJ4rkKBYOkLzcwik5d_fIi3OXQ', 'allowCredentials': [{'id': 'ux0q3g6u_ItvTGwm1jrop0OD5Wpl9dGWGQGyI93ViP12ow_OCKlb_4pIMdS3-rrWIbn5XnfTNAVBmGk1JZdGbuVla7cwI-qu7lZHVRDYdu8R8QrTEQmXxs3ZWyNFE2Wg', 'type': 'public-key', 'transports': ['usb']}], 'timeout': 60000, 'userVerification': 'preferred', 'rpId': 'localhost'}
    o = PublicKeyCredentialRequestOptions(
        challenge=unpadded_urlsafe_b64decode(r["challenge"]),
        timeout=r["timeout"],
        rp_id=r["rpId"],
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType(t["type"]),
                id=unpadded_urlsafe_b64decode(t["id"]),
                transports=[AuthenticatorTransport(tr) for tr in t["transports"]],
            )
            for t in r["allowCredentials"]
        ],
        user_verification=UserVerificationRequirement(r["userVerification"]),
        # extensions=None,
    )
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise SystemExit("No USB U2F key found")
    client = Fido2Client(dev, "https://localhost:5173", user_interaction=CliInteraction())
    results = client.get_assertion(o)
    result = results.get_response(0)
    print(f"{result.credential_id=}")
    print(f"{result.client_data=}")
    print(f"{result.authenticator_data=}")
    print(f"{result.signature=}")
    x = requests.post("https://localhost:5173/rp/auth-response", json={"userId": args.userid, "challenge": r["challenge"], "response": {
        "id": unpadded_urlsafe_b64encode(result.credential_id),
        "rawId": unpadded_urlsafe_b64encode(result.credential_id),
        "response": {
            "authenticatorData": unpadded_urlsafe_b64encode(result.authenticator_data),
            "clientDataJSON": unpadded_urlsafe_b64encode(result.client_data),
            "signature": unpadded_urlsafe_b64encode(result.signature),
        },
        "type": "public-key",
        "clientExtensionResults": {},
        }}, verify=False).json()
    print(x)


if __name__ == "__main__":
    main()
