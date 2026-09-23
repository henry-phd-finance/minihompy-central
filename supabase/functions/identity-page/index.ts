import { handleIdentityPageRequest } from "./handler.ts";
Deno.serve((req) => handleIdentityPageRequest(req));
