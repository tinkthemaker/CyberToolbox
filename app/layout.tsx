import type { Metadata } from "next";
import Link from "next/link";
import { headers } from "next/headers";
import { SITE } from "@/lib/tools/registry";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: SITE.name,
    template: `%s · ${SITE.name}`,
  },
  description: SITE.description,
  applicationName: SITE.name,
  authors: [{ name: SITE.name }],
  keywords: ["security", "appsec", "owasp", "jwt", "cors", "tls", "headers"],
  openGraph: {
    title: SITE.name,
    description: SITE.description,
    siteName: SITE.name,
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: SITE.name,
    description: SITE.description,
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = headers().get("x-nonce") ?? undefined;
  return (
    <html lang="en">
      <body className="font-sans antialiased" data-nonce={nonce}>
        <a href="#main" className="skip-link">Skip to main content</a>
        <header className="border-b border-ink-700/60 bg-ink-950/60 backdrop-blur sticky top-0 z-10">
          <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2 group">
              <span className="inline-block h-2.5 w-2.5 rounded-full bg-accent-500 shadow-[0_0_12px_rgba(56,189,248,0.7)]" />
              <span className="font-semibold tracking-tight group-hover:text-accent-400 transition">
                Cyber Toolbox
              </span>
            </Link>
            <nav className="text-sm text-slate-400 flex items-center gap-5">
              <Link href="/" className="hover:text-slate-200 transition">Tools</Link>
              <Link href="/about" className="hover:text-slate-200 transition">About</Link>
            </nav>
          </div>
        </header>
        <main id="main" className="mx-auto max-w-6xl px-6 py-10">{children}</main>
        <footer className="mx-auto max-w-6xl px-6 py-10 text-xs text-slate-500">
          <p>
            For authorized testing and educational use only. Only scan systems you own or have explicit
            permission to test.
          </p>
        </footer>
      </body>
    </html>
  );
}
