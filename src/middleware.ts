import { defineMiddleware } from "astro:middleware";
import { auth } from "@/lib/auth";
import { extractSubdomain } from "@/lib/routing/subdomain";
import { InMemoryRateLimiter } from "@/lib/utils/rate-limiter";

// Domain utama aplikasi, fallback ke domain Workers jika PUBLIC_MAIN_DOMAIN belum diatur
const MAIN_DOMAIN =
  import.meta.env.PUBLIC_MAIN_DOMAIN || "umkm-site-builder.ojangpetak.workers.dev";

// Tambahkan nama aplikasi/subdomain bawaan agar tidak dianggap sebagai storefront tenant
const RESERVED_SUBDOMAINS = new Set([
  "admin",
  "api",
  "www",
  "umkm-site-builder",
]);

// Inisialisasi Rate Limiter untuk API:
// 1. Read (GET): Longgar untuk memuat data (30 request / menit)
const apiReadLimiter = new InMemoryRateLimiter(30, 60 * 1000);
// 2. Write (POST/PUT/DELETE): Ketat untuk mencegah spam klik (5 request / menit)
const apiWriteLimiter = new InMemoryRateLimiter(5, 60 * 1000);

export const onRequest = defineMiddleware(async (context, next) => {
  // --- SUBDOMAIN DETECTION & REWRITE LOGIC ---
  const host = context.request.headers.get("host") || context.url.host || "";
  const { pathname } = context.url;

  // --- RATE LIMITING LOGIC ---
  if (pathname.startsWith("/api/")) {
    // Ambil IP pengunjung via Cloudflare header (cf-connecting-ip)
    let clientIp = "unknown";
    try {
      clientIp =
        context.request.headers.get("cf-connecting-ip") ||
        context.clientAddress ||
        context.request.headers.get("x-forwarded-for") ||
        "unknown";
    } catch {
      clientIp =
        context.request.headers.get("cf-connecting-ip") ||
        context.request.headers.get("x-forwarded-for") ||
        "unknown";
    }

    // Gunakan limiter yang sesuai berdasarkan HTTP Method
    const method = context.request.method;
    const isAllowed =
      method === "GET"
        ? apiReadLimiter.check(clientIp)
        : apiWriteLimiter.check(clientIp);

    if (!isAllowed) {
      return new Response(
        JSON.stringify({
          error: "Terlalu banyak permintaan. Silakan tunggu beberapa saat.",
        }),
        {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": "60",
          },
        }
      );
    }
  }

  const subdomain = extractSubdomain(host, MAIN_DOMAIN);

  // Simpan subdomain di locals agar bisa diakses di route handlers
  context.locals.subdomain = subdomain;

  // Cek apakah request ditujukan ke file statis atau endpoint sistem
  const isStaticOrSystemPath =
    pathname.startsWith("/api") ||
    pathname.startsWith("/_astro") ||
    pathname.startsWith("/storefront") ||
    pathname === "/favicon.ico" ||
    /\.(png|jpe?g|svg|css|js|ico|webp)$/i.test(pathname);

  // Rewrite internal ke route storefront jika ada subdomain valid (non-reserved & non-system)
  if (
    subdomain &&
    !RESERVED_SUBDOMAINS.has(subdomain.toLowerCase()) &&
    !isStaticOrSystemPath
  ) {
    const rewritePath =
      pathname === "/" || pathname === ""
        ? `/storefront/${subdomain}`
        : `/storefront/${subdomain}${pathname}`;
    return context.rewrite(rewritePath);
  }

  // --- AUTHENTICATION LOGIC ---
  try {
    const session = await auth.api.getSession({
      headers: context.request.headers,
    });

    if (session) {
      context.locals.user = session.user;
      context.locals.session = session.session;
    } else {
      context.locals.user = null;
      context.locals.session = null;
    }
  } catch {
    context.locals.user = null;
    context.locals.session = null;
  }

  const user = context.locals.user;

  // Redirect designer dari /dashboard ke /designer/wallet
  if (
    (pathname === "/dashboard" || pathname === "/dashboard/") &&
    user?.role === "designer"
  ) {
    return context.redirect("/designer/wallet");
  }

  // 1. Definisikan rute yang wajib diproteksi beserta role yang diizinkan
  const roleMap = [
    { prefix: "/admin/settings", roles: ["superadmin"] },
    { prefix: "/admin/template-categories", roles: ["superadmin"] },
    { prefix: "/admin/templates", roles: ["superadmin"] },
    { prefix: "/admin/whitelist", roles: ["superadmin"] },
    { prefix: "/admin/users", roles: ["superadmin"] },
    { prefix: "/api/admin/settings", roles: ["superadmin"] },
    { prefix: "/api/admin/template-categories", roles: ["superadmin"] },
    { prefix: "/api/admin/templates", roles: ["superadmin"] },
    { prefix: "/api/admin/whitelist", roles: ["superadmin"] },
    { prefix: "/api/admin/users", roles: ["superadmin"] },

    { prefix: "/admin", roles: ["admin", "superadmin"] },
    { prefix: "/api/admin", roles: ["admin", "superadmin"] },

    { prefix: "/dashboard", roles: ["tenant", "admin", "superadmin"] },
    { prefix: "/onboarding", roles: ["tenant", "admin", "superadmin"] },
    { prefix: "/builder", roles: ["designer", "tenant", "admin", "superadmin"] },
    { prefix: "/designer", roles: ["designer", "admin", "superadmin"] },
    { prefix: "/checkout", roles: ["tenant"] },
  ];

  // 2. Cek apakah rute saat ini termasuk dalam daftar proteksi
  const protectedRoute = roleMap.find((route) =>
    pathname.startsWith(route.prefix)
  );

  if (protectedRoute) {
    if (!user) {
      if (pathname.startsWith("/api/")) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }
      return context.redirect("/401");
    }

    if ((user as { status?: string }).status === "suspended") {
      if (pathname.startsWith("/api/")) {
        return new Response(
          JSON.stringify({ error: "Akun Anda ditangguhkan" }),
          {
            status: 403,
            headers: { "Content-Type": "application/json" },
          }
        );
      }
      return context.redirect("/auth/login?error=account_suspended");
    }

    if (!protectedRoute.roles.includes(user.role as string)) {
      if (pathname.startsWith("/api/")) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }
      return context.redirect("/403");
    }
  }

  return next();
});