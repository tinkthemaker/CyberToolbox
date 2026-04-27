export default function AboutPage() {
  return (
    <article className="prose prose-invert max-w-3xl">
      <h1 className="text-3xl font-bold tracking-tight">About</h1>
      <p className="text-slate-400 mt-4 leading-relaxed">
        Cyber Toolbox is a small, growing collection of single-purpose web-security utilities. The
        goal is to make AppSec basics — security headers, common misconfigurations, exposure
        checks — fast to run and easy to explain.
      </p>
      <h2 className="text-xl font-semibold mt-8">Ground rules</h2>
      <ul className="list-disc pl-5 mt-2 space-y-1 text-slate-400">
        <li>Only scan systems you own or have explicit permission to test.</li>
        <li>Tools refuse to scan private, loopback, or cloud-metadata addresses.</li>
        <li>All scans run server-side; nothing in the browser bypasses these guards.</li>
        <li>Findings are heuristics — verify before reporting.</li>
      </ul>
      <h2 className="text-xl font-semibold mt-8">Stack</h2>
      <p className="text-slate-400 mt-2 leading-relaxed">
        Next.js (App Router) on Vercel, TypeScript, Tailwind. Each tool is a self-contained module
        — UI under <code className="font-mono text-accent-400">app/tools/&lt;id&gt;</code>, API
        under <code className="font-mono text-accent-400">app/api/tools/&lt;id&gt;</code>, registry
        entry in <code className="font-mono text-accent-400">lib/tools/registry.ts</code>.
      </p>
    </article>
  );
}
