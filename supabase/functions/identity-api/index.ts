import { handleIdentityApiRequest } from "./handler.ts";
// Transport peer may be a shared gateway; do not substitute untrusted forwarding headers.
Deno.serve((req, info) => handleIdentityApiRequest(req, { transportPeerIp: info.remoteAddr.hostname }));
