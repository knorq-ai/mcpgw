import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAudit } from "../api/client";
import Badge from "../components/Badge";
import DataTable from "../components/DataTable";
import type { AuditEntry } from "../api/types";

const PAGE_SIZE = 50;

export default function AuditLog() {
  const [page, setPage] = useState(0);
  const [direction, setDirection] = useState("");
  const [action, setAction] = useState("");
  const [method, setMethod] = useState("");
  const [subject, setSubject] = useState("");
  const [upstream, setUpstream] = useState("");
  const [tool, setTool] = useState("");

  const { data } = useQuery({
    queryKey: ["audit", page, direction, action, method, subject, upstream, tool],
    queryFn: () =>
      fetchAudit({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        direction: direction || undefined,
        action: action || undefined,
        method: method || undefined,
        subject: subject || undefined,
        upstream: upstream || undefined,
        tool: tool || undefined,
      }),
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      render: (r: AuditEntry) => new Date(r.timestamp).toLocaleString(),
    },
    { key: "direction", header: "Direction", render: (r: AuditEntry) => r.direction },
    { key: "subject", header: "Subject", render: (r: AuditEntry) => r.subject ? <span className="font-mono text-xs">{r.subject}</span> : <span className="text-gray-300">—</span> },
    { key: "upstream", header: "Upstream", render: (r: AuditEntry) => r.upstream ? <span className="font-mono text-xs truncate max-w-[200px] block" title={r.upstream}>{r.upstream}</span> : <span className="text-gray-300">—</span> },
    { key: "method", header: "Method", render: (r: AuditEntry) => <span className="font-mono">{r.method || "—"}</span> },
    { key: "tool_name", header: "Tool", render: (r: AuditEntry) => {
      if (!r.tool_name) return <span className="text-gray-300">—</span>;
      const args = r.tool_args
        ? Object.entries(r.tool_args).map(([k, v]) => {
            const s = String(v);
            return `${k}=${s.length > 40 ? s.slice(0, 40) + "…" : s}`;
          })
        : [];
      return (
        <span className="font-mono text-xs">
          {r.tool_name}
          {args.length > 0 && (
            <span className="block text-gray-400">{args.join(", ")}</span>
          )}
        </span>
      );
    }},
    { key: "kind", header: "Kind", render: (r: AuditEntry) => r.kind },
    {
      key: "action",
      header: "Action",
      render: (r: AuditEntry) => (
        <Badge variant={r.action as "pass" | "block"}>{r.action}</Badge>
      ),
    },
    { key: "size", header: "Size", render: (r: AuditEntry) => `${r.size}B` },
    { key: "reason", header: "Reason", render: (r: AuditEntry) => r.reason || "—" },
  ];

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold text-gray-900">Audit Log</h1>

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          value={direction}
          onChange={(e) => { setDirection(e.target.value); setPage(0); }}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700"
        >
          <option value="">All Directions</option>
          <option value="c2s">Client → Server</option>
          <option value="s2c">Server → Client</option>
        </select>
        <select
          value={action}
          onChange={(e) => { setAction(e.target.value); setPage(0); }}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700"
        >
          <option value="">All Actions</option>
          <option value="pass">Pass</option>
          <option value="block">Block</option>
        </select>
        <input
          type="text"
          placeholder="Filter method..."
          value={method}
          onChange={(e) => { setMethod(e.target.value); setPage(0); }}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 placeholder-gray-400"
        />
        <input
          type="text"
          placeholder="Filter subject..."
          value={subject}
          onChange={(e) => { setSubject(e.target.value); setPage(0); }}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 placeholder-gray-400"
        />
        <input
          type="text"
          placeholder="Filter upstream..."
          value={upstream}
          onChange={(e) => { setUpstream(e.target.value); setPage(0); }}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 placeholder-gray-400"
        />
        <input
          type="text"
          placeholder="Filter tool..."
          value={tool}
          onChange={(e) => { setTool(e.target.value); setPage(0); }}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 placeholder-gray-400"
        />
        <span className="ml-auto text-sm text-gray-400">
          {data ? `${data.total} entries` : "—"}
        </span>
      </div>

      <DataTable
        columns={columns}
        data={data?.entries ?? []}
        keyExtractor={(_, i) => `${page}-${i}`}
      />

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-600 transition-colors hover:bg-gray-100 disabled:opacity-40"
          >
            Previous
          </button>
          <span className="text-sm text-gray-500">
            {page + 1} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-600 transition-colors hover:bg-gray-100 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
