import Link from "next/link";
import { TOOLS } from "@/lib/tools/registry";

export default function NotFound() {
  return (
    <div className="py-16">
      <div className="max-w-2xl">
        <p className="text-xs uppercase tracking-widest text-accent-400/80">404</p>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight mt-2">
          That tool isn&apos;t in the box.
        </h1>
        <p className="mt-4 text-slate-400 leading-relaxed">
          The page you&apos;re looking for doesn&apos;t exist (yet). Here&apos;s what is available:
        </p>
      </div>
      <ul className="mt-8 grid gap-2 max-w-2xl">
        {TOOLS.filter((t) => t.status === "live").map((t) => (
          <li key={t.id}>
            <Link
              href={t.href}
              className="block rounded-xl border border-ink-700 bg-ink-900/40 hover:border-accent-500/50 hover:bg-ink-800/60 px-4 py-3 transition"
            >
              <p className="text-slate-100 font-medium">{t.name}</p>
              <p className="text-sm text-slate-400">{t.tagline}</p>
            </Link>
          </li>
        ))}
      </ul>
      <p className="mt-8 text-sm">
        <Link href="/" className="text-accent-400 hover:text-accent-300 transition">
          ← Back to the toolbox
        </Link>
      </p>
    </div>
  );
}
