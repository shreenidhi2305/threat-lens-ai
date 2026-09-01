import { useAuth } from '../auth/AuthContext';

export function ProfilePage() {
  const { user } = useAuth();

  return (
    <div className="max-w-md space-y-4">
      <h2 className="text-2xl font-semibold">Profile</h2>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm">
        <div className="flex justify-between border-b border-slate-800 py-2">
          <span className="text-slate-500">User ID</span>
          <span className="font-mono text-xs text-slate-300">{user?.id}</span>
        </div>
        <div className="flex justify-between border-b border-slate-800 py-2">
          <span className="text-slate-500">Email</span>
          <span className="text-slate-300">{user?.email}</span>
        </div>
        <div className="flex justify-between py-2">
          <span className="text-slate-500">Role</span>
          <span className="text-cyan-400">{user?.role}</span>
        </div>
      </div>
      <p className="text-xs text-slate-600">Source: GET /api/v1/users/me</p>
    </div>
  );
}
