import { ToolCard } from "@/components/ToolCard";
import { TOOLS } from "@/lib/tools/registry";

export default function HomePage() {
  return (
    <div>
      <section className="py-8">
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
          Small, focused <span className="text-accent-400">web-security</span> tools.
        </h1>
        <p className="mt-4 text-slate-400 max-w-2xl leading-relaxed">
          A growing collection of single-purpose utilities for AppSec basics. Each tool is designed
          to do one thing well, explain its findings clearly, and be safe to run from a browser.
        </p>
      </section>
      <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {TOOLS.map((tool) => (
          <ToolCard key={tool.id} tool={tool} />
        ))}
      </section>
    </div>
  );
}
