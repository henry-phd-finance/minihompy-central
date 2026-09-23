import { handleIdentityApiRequest } from "./handler.ts";
Deno.serve((req) => handleIdentityApiRequest(req));
