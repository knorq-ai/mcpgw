interface Props {
  variant: "pass" | "block" | "allow" | "deny" | "enforce" | "audit" | "closed" | "open" | "half-open" | "disabled" | "approved" | "denied" | "pending" | "low" | "medium" | "high" | "redact";
  children: React.ReactNode;
}

const styles: Record<string, string> = {
  pass: "bg-emerald-50 text-emerald-700",
  allow: "bg-emerald-50 text-emerald-700",
  enforce: "bg-emerald-50 text-emerald-700",
  closed: "bg-emerald-50 text-emerald-700",
  approved: "bg-emerald-50 text-emerald-700",
  low: "bg-emerald-50 text-emerald-700",
  block: "bg-red-50 text-red-700",
  deny: "bg-red-50 text-red-700",
  open: "bg-red-50 text-red-700",
  denied: "bg-red-50 text-red-700",
  high: "bg-red-50 text-red-700",
  audit: "bg-amber-50 text-amber-700",
  "half-open": "bg-amber-50 text-amber-700",
  pending: "bg-amber-50 text-amber-700",
  medium: "bg-amber-50 text-amber-700",
  redact: "bg-blue-50 text-blue-700",
  disabled: "bg-gray-50 text-gray-500",
};

export default function Badge({ variant, children }: Props) {
  const cls = styles[variant] ?? "bg-gray-50 text-gray-500";
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${cls}`}>
      {children}
    </span>
  );
}
