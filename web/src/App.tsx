import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import AuditLog from "./pages/AuditLog";
import Policies from "./pages/Policies";
import Status from "./pages/Status";
import Servers from "./pages/Servers";
import Analytics from "./pages/Analytics";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/audit" element={<AuditLog />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/servers" element={<Servers />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/status" element={<Status />} />
      </Route>
    </Routes>
  );
}
