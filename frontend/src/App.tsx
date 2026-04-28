import { Routes, Route, Navigate } from "react-router-dom";
import { Show } from "@clerk/react";
import { Layout } from "@/components/layout/Layout";
import { Landing } from "@/pages/Landing";
import { Marketing } from "@/pages/Marketing";
import { SearchPage } from "@/pages/Search";
import { Explore } from "@/pages/Explore";
import { AgentDetail } from "@/pages/AgentDetail";
import { TestAgent } from "@/pages/TestAgent";
import { TestInfo } from "@/pages/TestInfo";
import { Scans } from "@/pages/Scans";
import { Ranges } from "@/pages/Ranges";

function AuthenticatedApp() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Landing />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/explore" element={<Explore />} />
        <Route path="/agent/:id" element={<AgentDetail />} />
        <Route path="/agent/:id/test" element={<TestAgent />} />
        <Route path="/agent/:id/results" element={<TestInfo />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/ranges" element={<Ranges />} />
      </Route>
      {/* Catch-all redirect */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function UnauthenticatedApp() {
  return (
    <Routes>
      <Route path="*" element={<Marketing />} />
    </Routes>
  );
}

export default function App() {
  return (
    <>
      <Show when="signed-in">
        <AuthenticatedApp />
      </Show>
      <Show when="signed-out">
        <UnauthenticatedApp />
      </Show>
    </>
  );
}
