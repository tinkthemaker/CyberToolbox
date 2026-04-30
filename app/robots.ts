import type { MetadataRoute } from "next";
import { baseUrl } from "@/lib/tools/registry";

export const dynamic = "force-dynamic";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/", disallow: ["/api/"] }],
    sitemap: `${baseUrl()}/sitemap.xml`,
  };
}
