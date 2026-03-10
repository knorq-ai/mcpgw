import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAnalytics } from "../api/client";
import DataTable from "../components/DataTable";
import type { AnalyticsGroup } from "../api/types";

const tabs = [
  { key: "by-server", label: "By Server" },
  { key: "by-user", label: "By User" },
  { key: "by-tool", label: "By Tool" },
  { key: "threats", label: "Threats" },
] as const;

type Tab = (typeof tabs)[number]["key"];

export default function Analytics() {
  const [tab, setTab] = useState<Tab>("by-server");

  const { data } = useQuery({
    queryKey: ["analytics", tab],
    queryFn: () => fetchAnalytics(tab),
  });

  const columns = [
    { key: "key", header: "Key", render: (r: AnalyticsGroup) => <span className="font-mono text-xs">{r.key}</span> },
    { key: "total", header: "Total", render: (r: AnalyticsGroup) => r.total },
    { key: "passed", header: "Passed", render: (r: AnalyticsGroup) => r.passed },
    { key: "blocked", header: "Blocked", render: (r: AnalyticsGroup) => r.blocked },
    {
      key: "block_rate",
      header: "Block Rate",
      render: (r: AnalyticsGroup) => `${(r.block_rate * 100).toFixed(1)}%`,
    },
    {
      key: "top_tools",
      header: "Top Tools",
      render: (r: AnalyticsGroup) =>
        r.top_tools?.length ? (
          <span className="text-xs text-gray-500">{r.top_tools.join(", ")}</span>
        ) : (
          <span className="text-gray-300">—</span>
        ),
    },
  ];

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold text-gray-900">Analytics</h1>

      <div className="mb-4 flex gap-1 rounded-lg bg-gray-100 p-1">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              tab === t.key
                ? "bg-white text-gray-900 shadow-sm"
                : "text-gray-500 hover:text-gray-700"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <DataTable
        columns={columns}
        data={data?.groups ?? []}
        keyExtractor={(r) => r.key}
      />
    </div>
  );
}
