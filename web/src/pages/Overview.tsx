import { useQuery } from "@tanstack/react-query";
import { BarChart3, ShieldAlert, Users, Timer } from "lucide-react";
import { fetchStats, fetchAudit } from "../api/client";
import KPICard from "../components/KPICard";
import Badge from "../components/Badge";
import DataTable from "../components/DataTable";
import type { AuditEntry } from "../api/types";

export default function Overview() {
  const { data: stats } = useQuery({ queryKey: ["stats"], queryFn: fetchStats });
  const { data: audit } = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () => fetchAudit({ limit: 10 }),
  });

  const fmt = (n?: number) => (n != null ? n.toLocaleString() : "—");
  const pct = (n?: number) => (n != null ? `${(n * 100).toFixed(1)}%` : "—");
  const ms = (n?: number) => (n != null ? `${(n * 1000).toFixed(0)}ms` : "—");

  const methodEntries = stats?.requests_by_method
    ? Object.entries(stats.requests_by_method).sort((a, b) => b[1] - a[1])
    : [];

  const auditColumns = [
    {
      key: "timestamp",
      header: "Time",
      render: (r: AuditEntry) => new Date(r.timestamp).toLocaleTimeString(),
    },
    { key: "direction", header: "Dir", render: (r: AuditEntry) => r.direction },
    { key: "method", header: "Method", render: (r: AuditEntry) => r.method || "—" },
    { key: "tool_name", header: "Tool", render: (r: AuditEntry) => r.tool_name ? <span className="font-mono text-xs">{r.tool_name}</span> : <span className="text-gray-300">—</span> },
    {
      key: "action",
      header: "Action",
      render: (r: AuditEntry) => (
        <Badge variant={r.action as "pass" | "block"}>{r.action}</Badge>
      ),
    },
  ];

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold text-gray-900">Overview</h1>

      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KPICard icon={BarChart3} label="Total Requests" value={fmt(stats?.requests_total)} />
        <KPICard icon={ShieldAlert} label="Blocked" value={pct(stats?.blocked_rate)} delta={fmt(stats?.requests_blocked)} />
        <KPICard icon={Users} label="Active Sessions" value={fmt(stats?.active_sessions)} />
        <KPICard icon={Timer} label="p95 Latency" value={ms(stats?.latency_p95)} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Requests by Method */}
        <div className="rounded-2xl border border-gray-100 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-sm font-medium text-gray-500">Requests by Method</h2>
          {methodEntries.length === 0 ? (
            <p className="text-sm text-gray-400">No data</p>
          ) : (
            <div className="space-y-3">
              {methodEntries.map(([method, count]) => {
                const max = methodEntries[0][1];
                const pctWidth = max > 0 ? (count / max) * 100 : 0;
                return (
                  <div key={method}>
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-mono text-gray-700">{method}</span>
                      <span className="text-gray-500">{count.toLocaleString()}</span>
                    </div>
                    <div className="mt-1 h-1.5 rounded-full bg-gray-100">
                      <div
                        className="h-1.5 rounded-full bg-gray-900"
                        style={{ width: `${pctWidth}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Audit */}
        <div>
          <h2 className="mb-4 text-sm font-medium text-gray-500">Recent Audit</h2>
          <DataTable
            columns={auditColumns}
            data={audit?.entries ?? []}
            keyExtractor={(_, i) => String(i)}
          />
        </div>
      </div>
    </div>
  );
}
