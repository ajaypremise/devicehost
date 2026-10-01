import { NextResponse } from "next/server";

const DEVICE_API_PREFIXES = [
  "/api/enroll",
  "/api/heartbeat",
  "/api/removal",
  "/api/events",
  "/api/inventory",
  "/api/setup/redeem",
  "/api/setup/verify-support",
];

export function proxy(request) {
  const pathname = request.nextUrl.pathname;

  // Device endpoints authenticate themselves with enrollment/device tokens.
  if (DEVICE_API_PREFIXES.some((prefix) => pathname.startsWith(prefix))) {
    return NextResponse.next();
  }

  const expectedUser = process.env.DASHBOARD_USER;
  const expectedPassword = process.env.DASHBOARD_PASSWORD;

  // Fail closed: never expose dashboard/admin data until credentials exist.
  if (!expectedUser || !expectedPassword) {
    return new NextResponse(
      "DeviceHost dashboard is locked. Configure DASHBOARD_USER and DASHBOARD_PASSWORD in Vercel.",
      { status: 503 }
    );
  }

  const authorization = request.headers.get("authorization") || "";
  if (authorization.startsWith("Basic ")) {
    try {
      const decoded = atob(authorization.slice(6));
      const separator = decoded.indexOf(":");
      const user = separator >= 0 ? decoded.slice(0, separator) : "";
      const password = separator >= 0 ? decoded.slice(separator + 1) : "";

      if (user === expectedUser && password === expectedPassword) {
        return NextResponse.next();
      }
    } catch {
      // Treat malformed credentials as unauthorized.
    }
  }

  return new NextResponse("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="DeviceHost", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
