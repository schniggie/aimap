import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { Search } from "lucide-react";
import { Show, SignInButton, UserButton } from "@clerk/react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const navLinks = [
  { to: "/explore", label: "Explore" },
  { to: "/scans", label: "Scans" },
  { to: "/ranges", label: "Ranges" },
];

export function Navbar() {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const location = useLocation();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      navigate(`/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 h-14 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-full items-center px-6 gap-6">
        {/* Logo */}
        <Link to="/" className="font-mono font-bold text-lg text-white tracking-wider shrink-0">
          AIMAP
        </Link>

        {/* Search */}
        <form onSubmit={handleSearch} className="flex-1 max-w-xl">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search agents, IPs, tools, protocols..."
              className="pl-9 h-8 bg-secondary/50 border-border"
            />
          </div>
        </form>

        {/* Nav links */}
        <nav className="flex items-center gap-1 shrink-0">
          {navLinks.map((link) => (
            <Link
              key={link.to}
              to={link.to}
              className={cn(
                "px-3 py-1.5 text-sm font-medium transition-colors hover:text-foreground",
                location.pathname === link.to
                  ? "text-foreground bg-secondary"
                  : "text-muted-foreground"
              )}
            >
              {link.label}
            </Link>
          ))}
        </nav>

        {/* Auth */}
        <div className="flex items-center gap-2 shrink-0 ml-auto">
          <Show when="signed-out">
            <SignInButton>
              <button className="px-3 py-1.5 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors border border-border rounded-md">
                Sign in
              </button>
            </SignInButton>
          </Show>
          <Show when="signed-in">
            <UserButton />
          </Show>
        </div>
      </div>
    </header>
  );
}
