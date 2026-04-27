import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cyber Toolbox",
  description: "A growing collection of small, focused web-security tools.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
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
        <main className="mx-auto max-w-6xl px-6 py-10">{children}</main>
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
