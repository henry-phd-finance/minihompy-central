/**
 * Central Identity API Request Handler (ESM)
 */

import { getCorsHeaders, handleCorsPreflight } from "../_shared/cors.js";
import { validateHandle, validateRelativePath } from "../_shared/validation.js";
import { ApiError, readBody } from "../_shared/auth-proof.js";
import { SECURE_PATHS, handleSecureAuth } from "./secure-auth.js";
import { WRITING_PATHS, handleWritingAuth, writingSessionActive } from "./writing-auth.js";
import { isNavigationRequest, handleNavigation, safeNavigationSite } from "./navigation.js";
import { signToken, verifyToken } from "../_shared/tokens.js";

function getEnv(key) {
  if (typeof Deno !== "undefined" && Deno.env) {
    return Deno.env.get(key);
  }
  if (typeof process !== "undefined" && process.env) {
    return process.env[key];
  }
  return undefined;
}

export function getCentralSecret(options) {
  const secret = options?.centralSecret ?? getEnv("CENTRAL_TOKEN_SECRET");
  if (typeof secret !== 'string' || new TextEncoder().encode(secret).length < 32) {
    throw new ApiError(503, '중앙 전용 서명키가 설정되지 않았습니다.');
  }
  return secret;
}

async function resolveSupabaseClient(options) {
  if (options?.supabaseClient) return options.supabaseClient;
  const url = getEnv("SUPABASE_URL");
  const key = getEnv("CENTRAL_SERVICE_ROLE_KEY") || getEnv("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return null;

  if (typeof Deno !== "undefined") {
    const { createClient } = await import("npm:@supabase/supabase-js@2.39.8");
    return createClient(url, key, {
      db: { schema: "private" },
      auth: { persistSession: false },
    });
  }
  return null;
}

let cachedOrigins = null;
let lastOriginsFetched = 0;
const CACHE_TTL_MS = 60_000;

export async function resolveAllowedOrigins(supabaseClient, options) {
  if (options?.allowedOrigins) {
    return options.allowedOrigins;
  }

  const now = Date.now();
  if (cachedOrigins && now - lastOriginsFetched < CACHE_TTL_MS) {
    return cachedOrigins;
  }

  const origins = new Set(
    options?.defaultAllowedOrigins || [
      "http://localhost:3000",
      "http://localhost:5000",
      "http://localhost:5173",
      "http://localhost:8000",
      "http://localhost:54321",
      "http://localhost:54323",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:5000",
      "http://127.0.0.1:5173",
      "http://127.0.0.1:8000",
      "http://127.0.0.1:54321",
      "http://127.0.0.1:54323",
    ]
  );

  const centralOrigin = options?.centralOrigin || getEnv("CENTRAL_ORIGIN");
  if (centralOrigin) origins.add(centralOrigin);

  const supabaseUrl = getEnv("SUPABASE_URL");
  if (supabaseUrl) {
    try {
      origins.add(new URL(supabaseUrl).origin);
    } catch { /* ignore */ }
  }

  if (supabaseClient) {
    try {
      const { data, error } = await supabaseClient
        .from("identity_sites")
        .select("origin")
        .eq("status", "active")
        .eq("verification_status", "verified");

      if (!error && Array.isArray(data)) {
        for (const row of data) {
          if (row.origin) origins.add(row.origin);
        }
      }
    } catch (err) {
      console.error("Failed to load allowed origins from database:", err);
    }
  }

  cachedOrigins = origins;
  lastOriginsFetched = now;
  return origins;
}

export function normalizeApiPath(pathname) {
  let p = pathname;
  if (p.startsWith("/functions/v1/identity-api")) {
    p = p.slice("/functions/v1/identity-api".length);
  } else if (p.startsWith("/identity-api")) {
    p = p.slice("/identity-api".length);
  }
  if (!p.startsWith("/")) {
    p = "/" + p;
  }
  if (p.length > 1 && p.endsWith("/")) {
    p = p.slice(0, -1);
  }
  return p;
}

export async function handleIdentityApiRequest(req, options) {
  const url = new URL(req.url);
  const path = normalizeApiPath(url.pathname);
  const origin = req.headers.get("Origin");

  // 1. GET /health - open to all origins without CORS restrictions
  if (path === "/health" && req.method === "GET") {
    return new Response(
      JSON.stringify({ status: "ok", identity_protocol: 2, writing_protocol: 1, member_session_protocol: 2, navigation_protocol: 1, timestamp: new Date().toISOString() }),
      {
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET",
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Resolve supabase client, secret and allowed origins
  const supabase = await resolveSupabaseClient(options);
  const allowedOrigins = await resolveAllowedOrigins(supabase, options);

  // Same-origin (자체 도메인에서 호출하는 identity-page 등)은 무조건 허용
  if (url.origin) {
    allowedOrigins.add(url.origin);
  }

  // 2. CORS Preflight
  const corsPreflight = handleCorsPreflight(req, allowedOrigins);
  if (corsPreflight) return corsPreflight;

  // 3. Origin check for browser cross-origin requests
  if (origin && origin !== url.origin && !allowedOrigins.has(origin)) {
    return new Response(
      JSON.stringify({ error: "Forbidden: Origin not allowed" }),
      {
        status: 403,
        headers: {
          "Content-Type": "application/json",
          "Vary": "Origin",
        },
      }
    );
  }

  const headers = {
    ...getCorsHeaders(origin, allowedOrigins),
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  try {
    if (isNavigationRequest(path, url.searchParams)) {
      const result = await handleNavigation(req, path, supabase);
      return new Response(JSON.stringify(result.body), { status: result.status, headers });
    }
    const secret = path === "/directory" ? null : getCentralSecret(options);
    if (WRITING_PATHS.has(path)) {
      const result = await handleWritingAuth(req, path, { db: supabase, secret });
      return new Response(JSON.stringify(result.body), { status: result.status, headers });
    }
    if (SECURE_PATHS.has(path) && req.method === 'POST') {
      const result = await handleSecureAuth(req, path, { db: supabase, secret, fetcher: options?.fetcher });
      return new Response(JSON.stringify(result.body), { status: result.status, headers });
    }
    // ------------------------------------------------------------------------
    // 4. GET /directory
    // ------------------------------------------------------------------------
    if (path === "/directory" && req.method === "GET") {
      const handleParam = url.searchParams.get("handle");
      const queryParam = url.searchParams.get("q") || url.searchParams.get("query");

      if (!handleParam && !queryParam) {
        return new Response(
          JSON.stringify({ error: "handle 또는 검색어를 입력해야 합니다." }),
          { status: 400, headers }
        );
      }

      if (!supabase) {
        return new Response(
          JSON.stringify({ error: "Database not available", items: [] }),
          { status: 503, headers }
        );
      }

      let members = [];

      if (handleParam) {
        let normalizedHandle;
        try {
          if (handleParam.length > 100) throw Error("handle이 너무 깁니다.");
          normalizedHandle = validateHandle(handleParam);
        } catch (e) {
          return new Response(
            JSON.stringify({ error: e.message || "유효하지 않은 handle입니다." }),
            { status: 400, headers }
          );
        }

        const { data, error } = await supabase
          .from("identity_members")
          .select("id, handle, display_name")
          .eq("status", "active")
          .eq("handle", normalizedHandle);

        if (error) {
          console.error("Database query error:", error);
          return new Response(JSON.stringify({ error: "데이터베이스 조회 실패" }), {
            status: 500,
            headers,
          });
        }
        members = data || [];
      } else if (queryParam) {
        const trimmed = queryParam.trim();
        if (queryParam.length > 100 || trimmed.length < 2 || trimmed.length > 30 || /[\u0000-\u001f\u007f]/u.test(trimmed)) {
          return new Response(
            JSON.stringify({ error: "검색어는 제어 문자 없이 2~30자로 입력해야 합니다." }),
            { status: 400, headers }
          );
        }

        const normalizedQ = trimmed.toLowerCase();
        const { data, error } = await supabase
          .from("identity_members")
          .select("id, handle, display_name")
          .eq("status", "active")
          .ilike("handle", `%${normalizedQ}%`)
          .limit(10);

        if (error) {
          console.error("Database query error:", error);
          return new Response(JSON.stringify({ error: "데이터베이스 조회 실패" }), {
            status: 500,
            headers,
          });
        }
        members = data || [];
      }

      if (members.length === 0) {
        return new Response(JSON.stringify({ items: [] }), { status: 200, headers });
      }

      const memberIds = members.map((m) => m.id);
      const { data: sites, error: sitesError } = await supabase
        .from("identity_sites")
        .select("member_id, homepage_url, origin, base_path")
        .eq("status", "active")
        .eq("verification_status", "verified")
        .in("member_id", memberIds);

      if (sitesError) {
        console.error("Sites query error:", sitesError);
        return new Response(JSON.stringify({ error: "사이트 정보 조회 실패" }), {
          status: 500,
          headers,
        });
      }

      const siteMap = new Map(
        (sites || []).filter(safeNavigationSite).map((s) => [s.member_id, s.homepage_url])
      );

      // Only include members with an active homepage_url
      // Profile strictly limited to: id, handle, display_name, homepage_url
      const items = members
        .filter((m) => siteMap.has(m.id))
        .map((m) => ({
          id: m.id,
          handle: m.handle,
          display_name: m.display_name,
          homepage_url: siteMap.get(m.id),
        }));

      return new Response(JSON.stringify({ items }), { status: 200, headers });
    }

    // ------------------------------------------------------------------------
    // 8. POST /visits/issue
    // ------------------------------------------------------------------------
    if (path === "/visits/issue" && req.method === "POST") {
      if (!supabase) {
        return new Response(
          JSON.stringify({ error: "Database not available" }),
          { status: 503, headers }
        );
      }

      let body;
      try {
        body = await readBody(req);
      } catch {
        return new Response(JSON.stringify({ error: "유효한 JSON 요청 본문이 필요합니다." }), {
          status: 400,
          headers,
        });
      }

      const { central_session, target_site_id, site_id, return_path, attempt_id, writing_protocol, code_challenge } = body || {};
      const actualSiteId = target_site_id || site_id;
      if (writing_protocol !== undefined && (writing_protocol !== 2 || typeof code_challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(code_challenge) || typeof attempt_id !== 'string' || !attempt_id || attempt_id.length>128 || /[\u0000-\u001f\u007f]/.test(attempt_id))) {
        return new Response(JSON.stringify({error:'Invalid writing protocol parameters'}),{status:400,headers});
      }

      if (!actualSiteId || typeof actualSiteId !== "string") {
        return new Response(
          JSON.stringify({ error: "target_site_id가 필요합니다." }),
          { status: 400, headers }
        );
      }

      // 8.1 대상 사이트(B) 활성 상태 및 경로 검증
      const { data: targetSite, error: targetSiteError } = await supabase
        .from("identity_sites")
        .select("id, origin, base_path, status")
        .eq("id", actualSiteId)
        .eq("status", "active")
        .eq("verification_status", "verified")
        .maybeSingle();

      if (targetSiteError || !targetSite) {
        return new Response(
          JSON.stringify({ error: "유효한 대상 사이트를 찾을 수 없거나 비활성화되었습니다." }),
          { status: 400, headers }
        );
      }

      let validatedReturnPath;
      try {
        validatedReturnPath = validateRelativePath(return_path || "", targetSite.base_path);
      } catch (e) {
        return new Response(
          JSON.stringify({ error: `유효하지 않은 복귀 경로입니다: ${e.message}` }),
          { status: 400, headers }
        );
      }

      // 8.2 attempt_id 준비
      let actualAttemptId = typeof attempt_id === "string" ? attempt_id.trim() : "";
      if (!actualAttemptId || actualAttemptId.length > 128 || /[\u0000-\u001f\u007f]/.test(actualAttemptId)) {
        actualAttemptId = crypto.randomUUID();
      }

      // 8.3 central_session 검증 및 사용자 상태/버전 확인
      const now = Math.floor(Date.now() / 1000);
      let identifiedMemberId = null;
      let identifiedSessionVersion = null;
      let identifiedSessionId = null;
      let sessionStatus = "anonymous";
      let sessionInvalid = false;

      if (central_session && typeof central_session === "string") {
        try {
          const sessionPayload = await verifyToken(central_session, "central_session", secret, now);
          const { data: member, error: memberError } = await supabase
            .from("identity_members")
            .select("id, status, session_version")
            .eq("id", sessionPayload.sub)
            .maybeSingle();

          if (writing_protocol===2 && memberError) throw new ApiError(503,'방문자 확인 서버에 연결하지 못했습니다.');
          if (
            !memberError &&
            member &&
            member.status === "active" &&
            (member.session_version || 1) === sessionPayload.session_version
          ) {
            const { data: ownerSite, error: ownerSiteError } = await supabase.from("identity_sites")
              .select("id").eq("member_id", member.id).eq("status", "active")
              .eq("verification_status", "verified").maybeSingle();
            if(writing_protocol===2 && ownerSiteError) throw new ApiError(503,'방문자 확인 서버에 연결하지 못했습니다.');
            if (ownerSite && !ownerSiteError && await writingSessionActive(supabase, sessionPayload, writing_protocol===2)) {
              identifiedMemberId = member.id;
              identifiedSessionVersion = member.session_version;
              identifiedSessionId = sessionPayload.central_session_id || null;
              sessionStatus = "identified";
            } else { sessionInvalid = true; }
          } else {
            sessionInvalid = true;
          }
        } catch (e) {
          if(writing_protocol===2 && e instanceof ApiError && e.status===503) throw e;
          sessionInvalid = true;
        }
      }

      // 8.4 60초 방문자 식별표(visit_ticket) 발행
      const visitPayload = {
        kind: "visit_ticket",
        sub: identifiedMemberId,
        session_version: identifiedSessionVersion,
        ...(identifiedSessionId ? { central_session_id: identifiedSessionId } : {}),
        aud: targetSite.id,
        attempt_id: actualAttemptId,
        return_path: validatedReturnPath,
        iat: now,
        exp: now + 60,
      };

      const visitTicket = await signToken(visitPayload, secret);

      // 8.5 복귀 URL 구성 (fragment에 vt와 원본 상대 경로 보존)
      const hashIndex = validatedReturnPath.indexOf("#");
      const basePathPart = hashIndex !== -1 ? validatedReturnPath.slice(0, hashIndex) : validatedReturnPath;
      const baseReturnUrl = new URL(basePathPart || targetSite.base_path, targetSite.origin).toString();

      const fragmentParams = new URLSearchParams();
      fragmentParams.set("vt", visitTicket);
      if (validatedReturnPath) {
        fragmentParams.set("path", validatedReturnPath);
      }
      if (writing_protocol === 2 && sessionStatus === 'identified') {
        const issued = await handleWritingAuth(new Request(req.url,{method:'POST',body:JSON.stringify({central_session,target_site_id:actualSiteId,return_path:validatedReturnPath,code_challenge,protocol:2,attempt_id:actualAttemptId})}),'/writing-proofs/issue',{db:supabase,secret});
        fragmentParams.set('wp',issued.body.writing_proof);
      }
      const returnUrl = `${baseReturnUrl}#${fragmentParams.toString()}`;

      return new Response(
        JSON.stringify({
          visit_ticket: visitTicket,
          status: sessionStatus,
          session_invalid: sessionInvalid,
          target_site_id: targetSite.id,
          attempt_id: actualAttemptId,
          return_path: validatedReturnPath,
          return_url: returnUrl,
        }),
        { status: 200, headers }
      );
    }

    // ------------------------------------------------------------------------
    // 9. POST /visits/resolve
    // ------------------------------------------------------------------------
    if (path === "/visits/resolve" && req.method === "POST") {
      if (!supabase) {
        return new Response(
          JSON.stringify({ error: "Database not available" }),
          { status: 503, headers }
        );
      }

      let body;
      try {
        body = await req.json();
      } catch {
        return new Response(JSON.stringify({ error: "유효한 JSON 요청 본문이 필요합니다." }), {
          status: 400,
          headers,
        });
      }

      const { visit_token, visit_ticket, site_id, target_site_id } = body || {};
      const token = visit_token || visit_ticket;
      const actualSiteId = site_id || target_site_id;

      if (!token || typeof token !== "string") {
        return new Response(
          JSON.stringify({ error: "visit_token 또는 visit_ticket이 필요합니다." }),
          { status: 400, headers }
        );
      }
      if (!actualSiteId || typeof actualSiteId !== "string") {
        return new Response(
          JSON.stringify({ error: "site_id가 필요합니다." }),
          { status: 400, headers }
        );
      }

      // 9.1 대상 사이트 존재 및 활성 상태 확인
      const { data: targetSite, error: siteError } = await supabase
        .from("identity_sites")
        .select("id, status")
        .eq("id", actualSiteId)
        .eq("status", "active")
        .eq("verification_status", "verified")
        .maybeSingle();

      if (siteError || !targetSite) {
        return new Response(
          JSON.stringify({ error: "유효한 사이트 정보를 찾을 수 없거나 비활성화되었습니다." }),
          { status: 400, headers }
        );
      }

      // 9.2 방문자 식별표 서명 및 만료 검증
      const now = Math.floor(Date.now() / 1000);
      let ticketPayload;
      try {
        ticketPayload = await verifyToken(token, "visit_ticket", secret, now);
      } catch (e) {
        return new Response(
          JSON.stringify({ error: `유효하지 않거나 만료된 방문자 식별표입니다: ${e.message}` }),
          { status: 400, headers }
        );
      }

      // 9.3 대상 사이트 일치 여부(aud === actualSiteId) 확인
      if (ticketPayload.aud !== actualSiteId) {
        return new Response(
          JSON.stringify({ error: "방문자 식별표의 대상 사이트가 일치하지 않습니다." }),
          { status: 403, headers }
        );
      }

      // 9.4 익명 방문자 처리 (sub === null)
      if (!ticketPayload.sub) {
        return new Response(
          JSON.stringify({
            status: "anonymous",
            visitor: null,
            profile: null,
            attempt_id: ticketPayload.attempt_id,
            return_path: ticketPayload.return_path,
          }),
          { status: 200, headers }
        );
      }

      // 9.5 식별된 방문자 프로필 조회
      const { data: member, error: memberError } = await supabase
        .from("identity_members")
        .select("id, handle, display_name, status, session_version")
        .eq("id", ticketPayload.sub)
        .eq("status", "active")
        .maybeSingle();

      if (memberError || !member || ticketPayload.session_version !== member.session_version || !await writingSessionActive(supabase, ticketPayload)) {
        // 사용자가 탈퇴 또는 정지된 경우 안전하게 익명으로 전환
        return new Response(
          JSON.stringify({
            status: "anonymous",
            visitor: null,
            profile: null,
            attempt_id: ticketPayload.attempt_id,
            return_path: ticketPayload.return_path,
          }),
          { status: 200, headers }
        );
      }

      // 소유한 대표 미니홈피의 homepage_url 조회
      const { data: homeSite, error: homeSiteError } = await supabase
        .from("identity_sites")
        .select("homepage_url, status")
        .eq("member_id", member.id)
        .eq("status", "active")
        .eq("verification_status", "verified")
        .maybeSingle();

      if (!homeSite || homeSiteError) {
        return new Response(JSON.stringify({ status: "anonymous", visitor: null, profile: null,
          attempt_id: ticketPayload.attempt_id, return_path: ticketPayload.return_path }), { status: 200, headers });
      }

      const publicProfile = {
        id: member.id,
        handle: member.handle,
        display_name: member.display_name,
        homepage_url: homeSite?.homepage_url || null,
      };

      return new Response(
        JSON.stringify({
          status: "identified",
          profile: publicProfile,
          visitor: publicProfile,
          attempt_id: ticketPayload.attempt_id,
          return_path: ticketPayload.return_path,
        }),
        { status: 200, headers }
      );
    }

    // ------------------------------------------------------------------------
    // 11. 404 Not Found
    // ------------------------------------------------------------------------
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers,
    });
  } catch (err) {
    if (WRITING_PATHS.has(path)) return new Response(JSON.stringify({ error: { code: err.code || (err.status === 400 ? 'BAD_REQUEST' : 'IDENTITY_UNAVAILABLE'), message: '회원 작성 인증을 확인하지 못했습니다.' } }), { status: err.status || 503, headers: {...headers,...(err.status===429?{'Retry-After':'1'}:{})} });
    if (err instanceof ApiError) return new Response(JSON.stringify({ error: err.message }), { status: err.status, headers });
    console.error("Identity API request failed");
    return new Response(
      JSON.stringify({ error: "Internal Server Error" }),
      { status: 500, headers }
    );
  }
}
