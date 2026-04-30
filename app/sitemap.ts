import type { MetadataRoute } from "next";
import { TOOLS, baseUrl } from "@/lib/tools/registry";

export const dynamic = "force-dynamic";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = baseUrl();
  const lastModified = new Date();
  return [
    { url: `${base}/`, lastModified, changeFrequency: "weekly", priority: 1 },
    { url: `${base}/about`, lastModified, changeFrequency: "monthly", priority: 0.5 },
    ...TOOLS.filter((t) => t.status === "live").map((t) => ({
      url: `${base}${t.href}`,
      lastModified,
      changeFrequency: "monthly" as const,
      priority: 0.8,
    })),
  ];
}
