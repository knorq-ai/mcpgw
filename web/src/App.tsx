import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import AuditLog from "./pages/AuditLog";
import Policies from "./pages/Policies";
import Status from "./pages/Status";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/audit" element={<AuditLog />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/status" element={<Status />} />
      </Route>
    </Routes>
  );
}
