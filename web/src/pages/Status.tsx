import { useQuery } from "@tanstack/react-query";
import { fetchStatus, fetchPolicy } from "../api/client";
import Badge from "../components/Badge";

export default function Status() {
  const { data: status } = useQuery({ queryKey: ["status"], queryFn: fetchStatus });
  const { data: policy } = useQuery({ queryKey: ["policy"], queryFn: fetchPolicy });

  const cbState = status?.circuit_breaker || "disabled";
  const cbVariant = cbState as "closed" | "open" | "half-open" | "disabled";

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold text-gray-900">System Status</h1>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Upstream */}
        <div className="rounded-2xl border border-gray-100 bg-white p-6 shadow-sm">
          <h2 className="mb-3 text-sm font-medium text-gray-500">Upstream</h2>
          <div className="flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                status?.upstream_ready ? "bg-emerald-500" : "bg-red-500"
              }`}
            />
            <span className="font-mono text-sm text-gray-700">{status?.upstream || "—"}</span>
          </div>
          <p className="mt-2 text-xs text-gray-400">
            {status?.upstream_ready ? "Reachable" : "Unreachable"}
          </p>
        </div>

        {/* Circuit Breaker */}
        <div className="rounded-2xl border border-gray-100 bg-white p-6 shadow-sm">
          <h2 className="mb-3 text-sm font-medium text-gray-500">Circuit Breaker</h2>
          <Badge variant={cbVariant}>{cbState}</Badge>
        </div>

        {/* Active Sessions */}
        <div className="rounded-2xl border border-gray-100 bg-white p-6 shadow-sm">
          <h2 className="mb-3 text-sm font-medium text-gray-500">Active Sessions</h2>
          <span className="text-2xl font-semibold text-gray-900">
            {status?.active_sessions ?? "—"}
          </span>
        </div>

        {/* Policy Summary */}
        <div className="rounded-2xl border border-gray-100 bg-white p-6 shadow-sm">
          <h2 className="mb-3 text-sm font-medium text-gray-500">Policy</h2>
          {policy?.mode ? (
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Badge variant={policy.mode === "enforce" ? "enforce" : "audit"}>
                  {policy.mode}
                </Badge>
                {policy.version && (
                  <span className="text-xs text-gray-400">v{policy.version}</span>
                )}
              </div>
              <p className="text-sm text-gray-600">{policy.rules.length} rules loaded</p>
            </div>
          ) : (
            <p className="text-sm text-gray-400">No policy loaded</p>
          )}
        </div>
      </div>
    </div>
  );
}
