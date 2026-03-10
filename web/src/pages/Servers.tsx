import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchServers, approveServer, denyServer } from "../api/client";
import Badge from "../components/Badge";
import DataTable from "../components/DataTable";
import type { ServerInfo } from "../api/types";

export default function Servers() {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["servers"],
    queryFn: fetchServers,
    refetchInterval: 5000,
  });

  const approve = useMutation({
    mutationFn: approveServer,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["servers"] }),
  });

  const deny = useMutation({
    mutationFn: denyServer,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["servers"] }),
  });

  const columns = [
    {
      key: "upstream",
      header: "Upstream",
      render: (r: ServerInfo) => (
        <button
          className="font-mono text-xs text-blue-600 hover:underline text-left"
          onClick={() => setExpanded(expanded === r.upstream ? null : r.upstream)}
        >
          {r.upstream}
        </button>
      ),
    },
    {
      key: "tools",
      header: "Tools",
      render: (r: ServerInfo) => r.tools?.length ?? 0,
    },
    {
      key: "risk_level",
      header: "Risk Level",
      render: (r: ServerInfo) => (
        <Badge variant={r.risk_level as "low" | "medium" | "high"}>
          {r.risk_level}
        </Badge>
      ),
    },
    {
      key: "risk_score",
      header: "Score",
      render: (r: ServerInfo) => r.risk_score.toFixed(2),
    },
    {
      key: "status",
      header: "Status",
      render: (r: ServerInfo) => (
        <Badge variant={r.status as "approved" | "denied" | "pending"}>
          {r.status}
        </Badge>
      ),
    },
    {
      key: "discovered_at",
      header: "Discovered",
      render: (r: ServerInfo) =>
        r.discovered_at ? new Date(r.discovered_at).toLocaleString() : "—",
    },
    {
      key: "actions",
      header: "Actions",
      render: (r: ServerInfo) =>
        r.status === "pending" ? (
          <div className="flex gap-1">
            <button
              onClick={() => approve.mutate(r.upstream)}
              className="rounded bg-emerald-100 px-2 py-1 text-xs font-medium text-emerald-700 hover:bg-emerald-200"
            >
              Approve
            </button>
            <button
              onClick={() => deny.mutate(r.upstream)}
              className="rounded bg-red-100 px-2 py-1 text-xs font-medium text-red-700 hover:bg-red-200"
            >
              Deny
            </button>
          </div>
        ) : null,
    },
  ];

  const servers = data?.servers ?? [];

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold text-gray-900">
        Server Evaluation
      </h1>
      <p className="mb-4 text-sm text-gray-500">
        {servers.length} server(s) discovered
      </p>

      <DataTable
        columns={columns}
        data={servers}
        keyExtractor={(r) => r.upstream}
      />

      {expanded && (
        <div className="mt-4 rounded-lg border border-gray-200 bg-gray-50 p-4">
          <h3 className="mb-2 text-sm font-semibold text-gray-700">
            Tools — {expanded}
          </h3>
          <div className="flex flex-wrap gap-2">
            {servers
              .find((s) => s.upstream === expanded)
              ?.tools?.map((t) => (
                <span
                  key={t.name}
                  className="inline-flex items-center gap-1 rounded bg-white px-2 py-1 text-xs font-mono border border-gray-200"
                >
                  {t.name}
                  <Badge variant={t.risk_level as "low" | "medium" | "high"}>
                    {t.risk_level}
                  </Badge>
                </span>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
