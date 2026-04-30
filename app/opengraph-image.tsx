import { ImageResponse } from "next/og";
import { SITE, TOOLS } from "@/lib/tools/registry";

export const runtime = "edge";
export const alt = SITE.name;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function Image() {
  const liveTools = TOOLS.filter((t) => t.status === "live");
  const liveCount = liveTools.length;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: 80,
          background: "linear-gradient(135deg, #06080d 0%, #0b1424 60%, #0e2540 100%)",
          color: "#e6edf6",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div
            style={{
              display: "flex",
              width: 18,
              height: 18,
              borderRadius: 999,
              background: "#38bdf8",
              boxShadow: "0 0 32px rgba(56,189,248,0.9)",
            }}
          />
          <div style={{ display: "flex", fontSize: 32, color: "#94a3b8", letterSpacing: -0.5 }}>
            {SITE.name}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              fontSize: 88,
              fontWeight: 700,
              lineHeight: 1.05,
              letterSpacing: -2,
              color: "#f1f5f9",
            }}
          >
            <div style={{ display: "flex" }}>Small, focused</div>
            <div style={{ display: "flex", gap: 14 }}>
              <span style={{ color: "#7dd3fc" }}>web-security</span>
              <span>tools.</span>
            </div>
          </div>
          <div style={{ display: "flex", fontSize: 28, color: "#94a3b8", maxWidth: 980 }}>
            {liveCount} tool{liveCount === 1 ? "" : "s"} for OWASP basics — headers, JWTs, CORS, TLS.
          </div>
        </div>

        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {liveTools.map((t) => (
            <div
              key={t.id}
              style={{
                display: "flex",
                fontSize: 22,
                color: "#cbd5e1",
                background: "rgba(56,189,248,0.08)",
                border: "1px solid rgba(56,189,248,0.25)",
                borderRadius: 999,
                padding: "10px 22px",
              }}
            >
              {t.name}
            </div>
          ))}
        </div>
      </div>
    ),
    { ...size },
  );
}
