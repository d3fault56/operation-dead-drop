// Server-side proxy to the FastAPI backend. Keeps the backend URL (and any keys) off the client
// and avoids CORS. Only whitelisted paths are forwarded.
import { NextRequest, NextResponse } from "next/server";

const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";
const ALLOWED = /^(investigate|demos|health|investigations(\/DD-\d{5})?)$/;
const MAX_BODY = 48_000;

async function forward(req: NextRequest, path: string[]) {
  const p = path.join("/");
  if (!ALLOWED.test(p)) return NextResponse.json({ detail: "Not found" }, { status: 404 });
  const init: RequestInit = { method: req.method, headers: { "Content-Type": "application/json" }, cache: "no-store" };
  if (req.method === "POST") {
    const body = await req.text();
    if (body.length > MAX_BODY) return NextResponse.json({ detail: "Request too large" }, { status: 413 });
    init.body = body;
    const fwd = req.headers.get("x-forwarded-for");
    if (fwd) (init.headers as Record<string, string>)["x-forwarded-for"] = fwd;
  }
  try {
    const r = await fetch(`${BACKEND}/${p}`, { ...init, signal: AbortSignal.timeout(60_000) });
    const data = await r.text();
    return new NextResponse(data, { status: r.status, headers: { "Content-Type": "application/json" } });
  } catch {
    return NextResponse.json({ detail: "Investigation backend unreachable" }, { status: 502 });
  }
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return forward(req, (await ctx.params).path);
}
export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return forward(req, (await ctx.params).path);
}
