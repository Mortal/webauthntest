import { b64urldecode } from "../../shared.ts";

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export function decodeClientDataJSON(data: string): ClientDataJSON {
  const toString = Buffer.from(b64urldecode(data), "base64").toString("utf-8");
  const clientData: ClientDataJSON = JSON.parse(toString);

  return clientData;
}

export type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  tokenBinding?: {
    id?: string;
    status: 'present' | 'supported' | 'not-supported';
  };
};
