import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ClerkProvider, useAuth } from "@clerk/react";
import { setTokenGetter } from "./lib/auth";
import "./index.css";
import App from "./App.tsx";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

// Ensure dark mode is always active
document.documentElement.classList.add("dark");

/** Bridges Clerk's getToken into the API client so every fetch includes the JWT. */
function ClerkTokenBridge({ children }: { children: React.ReactNode }) {
  const { getToken } = useAuth();
  useEffect(() => {
    setTokenGetter(getToken);
  }, [getToken]);
  return children;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ClerkProvider afterSignOutUrl="/">
      <BrowserRouter>
        <QueryClientProvider client={queryClient}>
          <ClerkTokenBridge>
            <App />
          </ClerkTokenBridge>
        </QueryClientProvider>
      </BrowserRouter>
    </ClerkProvider>
  </StrictMode>
);
