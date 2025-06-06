// src/index.ts
import { proxyLinkHttp,usIps } from "./proxyLinkHttp.js";
import { isNetcraftIp, isNetcraftUa} from "./requestBlocker.js";
import CopilotInjection from "./CopilotInjection.html";

let XForwardedForIP = usIps[Math.floor(Math.random() * usIps.length)][0];
console.log(XForwardedForIP);

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

async function handleRequest(request, env,ctx) {
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader && upgradeHeader == "websocket") {
      return websocketPorxy(request);
    }
    const url = new URL(request.url);
       // 匹配路径 /apijs/copilot.js
  if (url.pathname === '/apijs/api.js') {
    // 使用 fetch 获取目标 URL 的内容
  //  const targetUrl = 'https://apijs.pages.dev/web/rp/copilotapi.js';
    const targetUrl = 'https://apijs.pages.dev/web/rp/cloudflare-api.js';
  //  const targetUrl = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    const response = await fetch(targetUrl);

    // 返回目标 URL 的内容
    return new Response(response.body, {
      headers: { 'Content-Type': 'application/javascript' }, // 设置正确的 Content-Type
    });
  }
      
    const porxyHostName = url.hostname;
    const porxyOrigin = url.origin;
    const porxyPort = url.port;
    const porxyProtocol = url.protocol;
    return proxyLinkHttp(request, [
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
        
      //代理原始地址
        url2.hostname = "copilot.microsoft.com";
        
      //代理加载核心bundle.js文件
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
      },
    async (config) => {
        const url2 = config.url;
        if (url2.searchParams.has("cprt")) {
          url2.hostname = url2.searchParams.get("cprt");
          url2.searchParams.delete("cprt");
          return config;
        }
        if (url2.searchParams.has("cprtp")) {
          url2.port = url2.searchParams.get("cprtp");
          url2.searchParams.delete("cprtp");
        }
        if (url2.searchParams.has("cprtl")) {
          url2.protocol = url2.searchParams.get("cprtl");
          url2.searchParams.delete("cprtl");
        }
        return config;
      } 
    ], [
      
      async (config) => {
        config.init.headers = new Headers(config.init.headers);
        return config;
      },

      // 新增全局CORS头部设置（响应处理阶段）
  async (config, res) => {
    const headers = new Headers(config.init.headers);
    // 设置CORS全局许可
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH");
    headers.set("Access-Control-Allow-Headers", "*");
    headers.set("Access-Control-Expose-Headers", "*");
    headers.set("Access-Control-Max-Age", "86400");
  /*  
    // 如果是OPTIONS预检请求直接返回
    if (config.init.method === "OPTIONS") {
      return new Response(null, { 
        status: 204,
        headers: headers
      });
    }
    */
    config.init.headers = headers;
    return config;
  },
      
 //注入修改首页以加载核心bundle.js文件
      async (config, res) => {
        const resHeaders = config.init.headers;
        const contentType = res.headers.get("Content-Type");
        if (!contentType || !contentType.startsWith("text/") && !contentType.startsWith("application/javascript") && !contentType.startsWith("application/x-javascript") && !contentType.startsWith("application/json")) {
          return config;
          }
        resHeaders.delete("Content-Md5");
        let retBody = await res.text();
        const resUrl = new URL(res.url);  
        
        retBody = retBody.replace(/copilot\.microsoft\.com(:[0-9]{1,6})?/g, `${porxyHostName}`);
        retBody = retBody.replace(/https?:\/\/studiostaticassetsprod\.azureedge\.net(:[0-9]{1,6})?/g, `${porxyOrigin}`);
        // 添加验证替换动作
    //     retBody = retBody.replace(/https?:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/g, `${porxyOrigin}/apijs/api.js`);
        
        if (resUrl.pathname == "/") {
          retBody = injectionHtmlToHead(retBody, CopilotInjection);
        }
/*
        // 修改 CSP 头部
      const cspHeader = resHeaders.get("Content-Security-Policy");
      if (cspHeader) {
        // 删除 CSP 头部
        resHeaders.delete("Content-Security-Policy");
      }
  */      
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
  }

async function websocketPorxy(request) {
  const reqUrl = new URL(request.url);
  reqUrl.hostname = "zbj.pages.dev";
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
function injectionHtmlToHead(html, sc) {
  return html.replace("<head>", `<head>${sc}`);
}
function injectionHtmlToBody(html, sc) {
  return html.replace("<body>", `<body>${sc}`);
}
