import { useQuery } from "@tanstack/react-query";
import {
  getEndpoints,
  getEndpointById,
  getStats,
  getGeoData,
  getGlobeData,
  searchEndpoints,
  getScans,
  getQueryPresets,
  getRanges,
  getAnalysis,
} from "@/lib/api";

// -- Endpoints ----------------------------------------------------------------

export function useEndpoints(params?: Parameters<typeof getEndpoints>[0]) {
  return useQuery({
    queryKey: ["endpoints", params],
    queryFn: () => getEndpoints(params),
  });
}

export function useEndpointById(id: string | undefined) {
  return useQuery({
    queryKey: ["endpoint", id],
    queryFn: () => getEndpointById(id!),
    enabled: !!id,
  });
}

// -- Stats / Geo --------------------------------------------------------------

export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: () => getStats(),
  });
}

export function useGeoData() {
  return useQuery({
    queryKey: ["geo"],
    queryFn: () => getGeoData(),
  });
}

export function useGlobeData() {
  return useQuery({
    queryKey: ["globe"],
    queryFn: () => getGlobeData(),
    staleTime: 60_000, // Cache for 1 min — globe data doesn't change fast
  });
}

// -- Search -------------------------------------------------------------------

export function useSearchEndpoints(
  query: string,
  page: number = 1,
  pageSize: number = 25
) {
  return useQuery({
    queryKey: ["search", query, page, pageSize],
    queryFn: () => searchEndpoints(query, page, pageSize),
    enabled: !!query,
  });
}

// -- Scans --------------------------------------------------------------------

export function useScans(params?: Parameters<typeof getScans>[0]) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => getScans(params),
  });
}

export function useQueryPresets() {
  return useQuery({
    queryKey: ["query-presets"],
    queryFn: () => getQueryPresets(),
  });
}

// -- Ranges -------------------------------------------------------------------

export function useRanges(params?: Parameters<typeof getRanges>[0]) {
  return useQuery({
    queryKey: ["ranges", params],
    queryFn: () => getRanges(params),
  });
}

// -- Analysis -----------------------------------------------------------------

export function useAnalysis(endpointId: string | undefined) {
  return useQuery({
    queryKey: ["analysis", endpointId],
    queryFn: () => getAnalysis(endpointId!),
    enabled: !!endpointId,
  });
}
