import { useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import Globe, { type GlobeInstance } from "globe.gl";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GlobePoint {
  id: string;
  ip: string;
  port: number;
  protocol: string;
  risk_score: number;
  auth_status: string;
  tool_count: number;
  lat: number;
  lng: number;
  country_code: string;
  city: string;
  hostname: string;
  model: string;
}

interface Props {
  points: GlobePoint[];
  height?: number;
  /** Show atmosphere glow (default true) */
  atmosphere?: boolean;
}

// ---------------------------------------------------------------------------
// Protocol → color map
// ---------------------------------------------------------------------------

const PROTOCOL_COLORS: Record<string, string> = {
  mcp: "#3b82f6",          // blue
  ollama: "#22c55e",       // green
  openai_compat: "#a855f7", // purple
  vllm: "#8b5cf6",        // violet
  litellm: "#7c3aed",     // violet
  gradio: "#f97316",       // orange
  comfyui: "#ec4899",     // pink
  open_webui: "#06b6d4",  // cyan
  streamlit: "#ef4444",   // red
  langserve: "#0ea5e9",   // sky
  huggingface: "#fbbf24",  // yellow
  unknown: "#6b7280",     // gray
};

const PROTOCOL_LABELS: Record<string, string> = {
  mcp: "MCP",
  ollama: "Ollama",
  openai_compat: "OpenAI",
  vllm: "vLLM",
  litellm: "LiteLLM",
  gradio: "Gradio",
  comfyui: "ComfyUI",
  open_webui: "Open WebUI",
  streamlit: "Streamlit",
  langserve: "LangServe",
  huggingface: "HuggingFace",
  unknown: "Unknown",
};

function riskLabel(score: number): string {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "INFO";
}

function riskColor(score: number): string {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#22c55e";
  return "#6b7280";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GlobeVisualization({ points, height = 500, atmosphere = true }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef = useRef<GlobeInstance | null>(null);
  const navigate = useNavigate();

  const handlePointClick = useCallback(
    (point: object) => {
      const p = point as GlobePoint;
      navigate(`/agent/${p.id}`);
    },
    [navigate],
  );

  useEffect(() => {
    if (!containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth;

    const globe = new Globe(container)
      // Globe appearance — dark theme
      .globeImageUrl(
        "//unpkg.com/three-globe/example/img/earth-night.jpg",
      )
      .backgroundImageUrl(
        "//unpkg.com/three-globe/example/img/night-sky.png",
      )
      .backgroundColor("rgba(0,0,0,0)")
      .showAtmosphere(atmosphere)
      .atmosphereColor("#3b82f6")
      .atmosphereAltitude(0.15)

      // Points config
      .pointsData(points)
      .pointLat("lat")
      .pointLng("lng")
      .pointAltitude((d: object) => {
        const p = d as GlobePoint;
        // Scale: risk 0 → 0.01, risk 100 → 0.6
        return 0.01 + (p.risk_score / 100) * 0.59;
      })
      .pointRadius((d: object) => {
        const p = d as GlobePoint;
        // Base size + risk bonus
        return 0.15 + (p.risk_score / 100) * 0.25;
      })
      .pointColor((d: object) => {
        const p = d as GlobePoint;
        return PROTOCOL_COLORS[p.protocol] || PROTOCOL_COLORS.unknown;
      })
      .pointLabel((d: object) => {
        const p = d as GlobePoint;
        const proto = PROTOCOL_LABELS[p.protocol] || p.protocol;
        const auth = p.auth_status === "none"
          ? '<span style="color:#ef4444">No Auth</span>'
          : p.auth_status === "api_key"
          ? "API Key"
          : p.auth_status;
        const riskLbl = riskLabel(p.risk_score);
        const riskClr = riskColor(p.risk_score);
        const location = [p.city, p.country_code].filter(Boolean).join(", ");

        return `
          <div style="
            background: rgba(10, 10, 20, 0.92);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 6px;
            padding: 10px 14px;
            font-family: ui-monospace, monospace;
            font-size: 12px;
            color: #e2e8f0;
            min-width: 200px;
            backdrop-filter: blur(8px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
          ">
            <div style="font-size: 13px; font-weight: 700; color: white; margin-bottom: 6px;">
              ${p.ip}:${p.port}
            </div>
            <div style="display: grid; grid-template-columns: auto 1fr; gap: 2px 10px;">
              <span style="color: #94a3b8;">Protocol</span>
              <span style="color: ${PROTOCOL_COLORS[p.protocol] || "#6b7280"}">${proto}</span>
              <span style="color: #94a3b8;">Risk</span>
              <span style="color: ${riskClr}; font-weight: 600;">${riskLbl} (${p.risk_score})</span>
              <span style="color: #94a3b8;">Auth</span>
              <span>${auth}</span>
              ${p.tool_count > 0 ? `<span style="color: #94a3b8;">Tools</span><span>${p.tool_count}</span>` : ""}
              ${p.model ? `<span style="color: #94a3b8;">Model</span><span>${p.model}</span>` : ""}
              ${p.hostname ? `<span style="color: #94a3b8;">Host</span><span style="word-break: break-all;">${p.hostname}</span>` : ""}
              ${location ? `<span style="color: #94a3b8;">Location</span><span>${location}</span>` : ""}
            </div>
            <div style="margin-top: 6px; font-size: 10px; color: #64748b; text-align: center;">
              Click to view details
            </div>
          </div>
        `;
      })

      // Interaction
      .onPointClick(handlePointClick)

      // Sizing
      .width(width)
      .height(height);

    globeRef.current = globe;

    // Auto-rotate
    const controls = globe.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.4;
    controls.enableZoom = true;
    controls.minDistance = 120;
    controls.maxDistance = 500;

    // Stop auto-rotate on user interaction, resume after idle
    let idleTimer: ReturnType<typeof setTimeout>;
    const pauseRotation = () => {
      controls.autoRotate = false;
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        controls.autoRotate = true;
      }, 5000);
    };

    container.addEventListener("mousedown", pauseRotation);
    container.addEventListener("touchstart", pauseRotation);
    container.addEventListener("wheel", pauseRotation);

    // Responsive resize
    const resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) {
          globe.width(w);
        }
      }
    });
    resizeObserver.observe(container);

    return () => {
      clearTimeout(idleTimer);
      container.removeEventListener("mousedown", pauseRotation);
      container.removeEventListener("touchstart", pauseRotation);
      container.removeEventListener("wheel", pauseRotation);
      resizeObserver.disconnect();

      // Clean up the globe renderer
      globe._destructor?.();

      // Remove children added by globe.gl
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
    };
  }, [points, height, atmosphere, handlePointClick]);

  // Update points data without re-creating the globe
  useEffect(() => {
    if (globeRef.current && points) {
      globeRef.current.pointsData(points);
    }
  }, [points]);

  return (
    <div
      ref={containerRef}
      style={{ width: "100%", height }}
      className="relative cursor-grab active:cursor-grabbing"
    />
  );
}

// ---------------------------------------------------------------------------
// Legend component
// ---------------------------------------------------------------------------

export function GlobeLegend({ points }: { points: GlobePoint[] }) {
  // Compute which protocols are actually present
  const protocols = Array.from(new Set(points.map((p) => p.protocol))).sort();

  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground px-2">
      {protocols.map((proto) => (
        <div key={proto} className="flex items-center gap-1.5">
          <span
            className="inline-block w-2.5 h-2.5 rounded-full"
            style={{ backgroundColor: PROTOCOL_COLORS[proto] || PROTOCOL_COLORS.unknown }}
          />
          <span>{PROTOCOL_LABELS[proto] || proto}</span>
          <span className="text-muted-foreground/60">
            ({points.filter((p) => p.protocol === proto).length})
          </span>
        </div>
      ))}
      <div className="flex items-center gap-1.5 ml-2 pl-2 border-l border-muted-foreground/20">
        <span className="text-muted-foreground/60">Pin height = risk score</span>
      </div>
    </div>
  );
}
