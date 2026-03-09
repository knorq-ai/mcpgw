import { useQuery } from "@tanstack/react-query";
import { fetchPolicy } from "../api/client";
import Badge from "../components/Badge";
import DataTable from "../components/DataTable";
import type { PolicyRule } from "../api/types";

export default function Policies() {
  const { data } = useQuery({ queryKey: ["policy"], queryFn: fetchPolicy });

  const columns = [
    { key: "name", header: "Name", render: (r: PolicyRule) => <span className="font-medium">{r.name}</span> },
    {
      key: "methods",
      header: "Methods",
      render: (r: PolicyRule) => (
        <div className="flex flex-wrap gap-1">
          {r.methods.map((m) => (
            <span key={m} className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs">{m}</span>
          ))}
        </div>
      ),
    },
    {
      key: "tools",
      header: "Tools",
      render: (r: PolicyRule) =>
        r.tools && r.tools.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {r.tools.map((t) => (
              <span key={t} className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs">{t}</span>
            ))}
          </div>
        ) : (
          <span className="text-gray-400">—</span>
        ),
    },
    {
      key: "arguments",
      header: "Arguments",
      render: (r: PolicyRule) => {
        const hasArgs = r.arguments && Object.keys(r.arguments).length > 0;
        const hasPatterns = r.argument_patterns && Object.keys(r.argument_patterns).length > 0;
        if (!hasArgs && !hasPatterns) return <span className="text-gray-400">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {r.arguments && Object.entries(r.arguments).map(([argName, patterns]) =>
              patterns.map((p) => (
                <span key={`${argName}:${p}`} className="rounded bg-amber-100 px-1.5 py-0.5 font-mono text-xs text-amber-800">
                  {argName}: {p}
                </span>
              ))
            )}
            {r.argument_patterns && Object.entries(r.argument_patterns).map(([argName, patterns]) =>
              patterns.map((p) => (
                <span key={`pat:${argName}:${p}`} className="rounded bg-purple-100 px-1.5 py-0.5 font-mono text-xs text-purple-800">
                  {argName}: /{p}/
                </span>
              ))
            )}
          </div>
        );
      },
    },
    {
      key: "subjects",
      header: "Subjects",
      render: (r: PolicyRule) =>
        r.subjects && r.subjects.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {r.subjects.map((s) => (
              <span key={s} className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs">{s}</span>
            ))}
          </div>
        ) : (
          <span className="text-gray-400">—</span>
        ),
    },
    {
      key: "action",
      header: "Action",
      render: (r: PolicyRule) => (
        <Badge variant={r.action as "allow" | "deny"}>{r.action}</Badge>
      ),
    },
    {
      key: "mode",
      header: "Mode",
      render: (r: PolicyRule) =>
        r.mode ? (
          <Badge variant={r.mode as "enforce" | "audit"}>{r.mode}</Badge>
        ) : (
          <span className="text-gray-400">—</span>
        ),
    },
  ];

  const mode = data?.mode || "";
  const modeVariant = mode === "enforce" ? "enforce" : mode === "audit" ? "audit" : "disabled";

  return (
    <div>
      <div className="mb-6 flex items-center gap-3">
        <h1 className="text-xl font-semibold text-gray-900">Policies</h1>
        {mode && <Badge variant={modeVariant}>{mode}</Badge>}
        {data?.version && <span className="text-sm text-gray-400">v{data.version}</span>}
      </div>

      <DataTable
        columns={columns}
        data={data?.rules ?? []}
        keyExtractor={(r) => r.name}
      />

      {(data?.response_patterns?.length || data?.allowed_tools?.length) && (
        <div className="mt-8 space-y-4">
          {data?.response_patterns && data.response_patterns.length > 0 && (
            <div>
              <h2 className="mb-2 text-lg font-medium text-gray-900">Response Patterns</h2>
              <div className="flex flex-wrap gap-1">
                {data.response_patterns.map((p) => (
                  <span key={p} className="rounded bg-red-100 px-1.5 py-0.5 font-mono text-xs text-red-800">
                    /{p}/
                  </span>
                ))}
              </div>
            </div>
          )}
          {data?.allowed_tools && data.allowed_tools.length > 0 && (
            <div>
              <h2 className="mb-2 text-lg font-medium text-gray-900">Allowed Tools</h2>
              <div className="flex flex-wrap gap-1">
                {data.allowed_tools.map((t) => (
                  <span key={t} className="rounded bg-green-100 px-1.5 py-0.5 font-mono text-xs text-green-800">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
