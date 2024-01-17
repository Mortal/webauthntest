
export const b64urlencode = (s: string) => s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const b64urldecode = (s: string) => s.replace(/-/g, "+").replace(/_/g, "/") + "====".substring(0, (4 - s.length % 4) % 4);

