export function ComingSoonPage({ title, milestone }: { title: string; milestone: number }) {
  return (
    <div className="max-w-lg rounded-lg border border-slate-800 bg-slate-900 p-8">
      <h2 className="text-2xl font-semibold">{title}</h2>
      <p className="mt-2 text-sm text-slate-500">
        This module is scheduled for <span className="text-cyan-400">Milestone {milestone}</span>.
        The route, navigation and RBAC gate are wired; the backend endpoint currently returns
        scaffold data.
      </p>
    </div>
  );
}
