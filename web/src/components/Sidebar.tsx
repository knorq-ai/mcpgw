import { NavLink } from "react-router-dom";
import { LayoutDashboard, ScrollText, ShieldCheck, Activity } from "lucide-react";

const items = [
  { to: "/", icon: LayoutDashboard, label: "Overview" },
  { to: "/audit", icon: ScrollText, label: "Audit Log" },
  { to: "/policies", icon: ShieldCheck, label: "Policies" },
  { to: "/status", icon: Activity, label: "Status" },
] as const;

export default function Sidebar() {
  return (
    <nav className="flex w-16 flex-col items-center gap-2 border-r border-gray-100 bg-white py-6">
      <div className="mb-4 text-xs font-bold tracking-wider text-gray-400">GW</div>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.to === "/"}
          className={({ isActive }) =>
            `flex h-10 w-10 items-center justify-center rounded-xl transition-colors ${
              isActive
                ? "bg-gray-900 text-white"
                : "text-gray-400 hover:bg-gray-100 hover:text-gray-600"
            }`
          }
          title={item.label}
        >
          <item.icon size={20} />
        </NavLink>
      ))}
    </nav>
  );
}
