// src/index.ts
import { proxyLinkHttp, usIps } from "./proxyLinkHttp.js";
import { isNetcraftIp, isNetcraftUa } from "./requestBlocker.js";
import CopilotInjection from "./CopilotInjection.html";

let XForwardedForIP = usIps[Math.floor(Math.random() * usIps.length)][0];
console.log(XForwardedForIP);

// 生成一个随机的 nonce 值
async function generateNonce() {
  const array = new Uint8Array(16); // 16 字节的随机值
  crypto.getRandomValues(array); // 使用 Web Crypto API 生成随机值
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join(''); // 转换为十六进制字符串
}

export async function onRequest(context) {
  const { request, env } = context;
  const clientIP = request.headers.get("CF-Connecting-IP");
  const userAgent = request.headers.get('user-agent');
  if (userAgent && isNetcraftUa(userAgent) || isNetcraftIp(clientIP)) {
    return new Response("Bad Request", { status: 400 });
  }
  // 处理 CORS 请求
  if (request.method === 'OPTIONS') {
    return handleOptions(request);
  }
  // 处理普通 HTTP 请求
  return handleRequest(request, env);
}

function handleOptions(request) {
  // 设置 CORS 头部
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
    'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '',
    'Access-Control-Max-Age': '86400',
  };
  return new Response(null, { headers: corsHeaders });
}

async function handleRequest(request, env, ctx) {
  const upgradeHeader = request.headers.get("Upgrade");
  if (upgradeHeader && upgradeHeader === "websocket") {
    return websocketPorxy(request);
  }

  const url = new URL(request.url);
  const porxyHostName = url.hostname;
  const porxyOrigin = url.origin;
  const porxyPort = url.port;
  const porxyProtocol = url.protocol;

  // 生成 nonce
  const nonce = await generateNonce();

  const response = await proxyLinkHttp(request, [
    async (config) => {
      const url2 = new URL(config.url);
      url2.port = "";
      url2.protocol = "https:";
      config.url = url2;
      config.init.headers = new Headers(config.init.headers);
      return config;
    },

    async (config) => {
      const url2 = config.url;
      const p = url2.pathname;

      // 代理原始地址
      url2.hostname = "copilot.microsoft.com";

      // 代理加载核心 bundle.js 文件
      if (p.startsWith("/bundle-cmc/") || p.startsWith("/bundle-wpwa/")) {
        url2.hostname = "studiostaticassetsprod.azureedge.net";
      }

      return config;
    },

    async (config) => {
      const resHeaders = config.init.headers;
      resHeaders.set("X-forwarded-for", XForwardedForIP);
      return config;
    },

    async (config) => {
      const resHeaders = config.init.headers;
      const origin = resHeaders.get("Origin");
      if (origin) {
        const url2 = config.url;
        const originUrl = new URL(origin);
        originUrl.protocol = "https:";
        originUrl.port = "";
        originUrl.hostname = "copilot.microsoft.com";
        resHeaders.set("Origin", originUrl.origin);
      }
      return config;
    },

    async (config) => {
      const resHeaders = config.init.headers;
      const referer = resHeaders.get("Referer");
      if (referer) {
        const url2 = config.url;
        let refererUrl = new URL(referer);
        refererUrl.protocol = "https:";
        refererUrl.port = "";
        refererUrl.hostname = "copilot.microsoft.com";
        resHeaders.set("Referer", refererUrl.toString());
      }
      return config;
    }
  ], [
    async (config) => {
      config.init.headers = new Headers(config.init.headers);
      return config;
    },

    // 注入修改首页以加载核心 bundle.js 文件
    async (config, res) => {
      const resHeaders = config.init.headers;
      const contentType = res.headers.get("Content-Type");
      if (!contentType || !contentType.startsWith("text/") && !contentType.startsWith("application/javascript") && !contentType.startsWith("application/x-javascript") && !contentType.startsWith("application/json")) {
        return config;
      }
      resHeaders.delete("Content-Md5");
      let retBody = await res.text();
      const resUrl = new URL(res.url);
      if (resUrl.pathname === "/") {
        retBody = injectionHtmlToHead(retBody, CopilotInjection, nonce); // 注入 nonce
      }
      config.body = retBody;
      return config;
    },

    async (config, res) => {
      if (res.status < 300 || res.status >= 400) {
        return config;
      }
      const resHeaders = config.init.headers;
      const loto = resHeaders.get("Location");
      if (!loto) {
        return config;
      }
      if (!loto.toLowerCase().startsWith("http")) {
        return config;
      }
      const lotoUrl = new URL(loto);
      lotoUrl.hostname = porxyHostName;
      lotoUrl.port = porxyPort;
      lotoUrl.protocol = porxyProtocol;
      resHeaders.set("Location", lotoUrl.toString());
      return config;
    }
  ]);

 // 设置 CSP 头部，允许本机 JavaScript 执行
  const cspHeader = `
    base-uri 'self';
    script-src 'strict-dynamic' https://www.clarity.ms https://copilot.microsoft.com https://picassostaticassetsstg.azureedge.net/ https://challenges.cloudflare.com/ 'self' 'nonce-${nonce}' 'unsafe-inline';
    require-trusted-types-for 'script';
    trusted-types default copilotPolicy dompurify @centro/hvc-loader;
    frame-ancestors 'self' https://edgeservices.bing.com edge://* teams.microsoft.com teams.live.com local.teams.office.com local.teams.live.com *.microsoft365.com *.office.com m365.cloud.microsoft copilot.cloud.microsoft ccm.mobile.m365.svc.cloud.microsoft copilot.cloud-dev.microsoft https://travel-dev.aexp.com/ https://travel-qa.aexp.com https://travel.aexp.com https://travelpreflight-dev.aexp.com https://travelpreflight-qa.aexp.com https://travelpreflight.aexp.com;
    report-to csp-endpoint;
  `.replace(/\s+/g, ' ').trim(); // 去除多余空格

  const newHeaders = new Headers(response.headers);
  newHeaders.set("Content-Security-Policy", cspHeader);

  return new Response(response.body, {
    status: response.status,
    headers: newHeaders,
  });
}

async function websocketPorxy(request) {
  const reqUrl = new URL(request.url);
  reqUrl.hostname = "copilot.microsoft.com";
  reqUrl.protocol = "https:";
  reqUrl.port = "";
  const headers = new Headers(request.headers);
  if (headers.get("origin")) {
    headers.set("origin", "https://copilot.microsoft.com");
  }
  headers.append("X-forwarded-for", XForwardedForIP);
  return fetch(reqUrl, {
    body: request.body,
    headers,
    method: request.method
  });
}

function injectionHtmlToHead(html, sc, nonce) {
  return html.replace("<head>", `<head><script nonce="${nonce}">${sc}</script>`);
}

function injectionHtmlToBody(html, sc, nonce) {
  return html.replace("<body>", `<body><script nonce="${nonce}">${sc}</script>`);
}
