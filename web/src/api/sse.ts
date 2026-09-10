import { useEffect, useRef, useState } from "react";
import type { AuditEvent } from "./types";

export interface LiveFeedState {
  events: AuditEvent[];
  connected: boolean;
  dropped: number;
  clear: () => void;
}

/**
 * Subscribes to the audit event stream while `enabled`. The server sends a
 * `dropped` event when the viewer's feed could not keep up; that count is
 * surfaced so the UI never presents a gap as a complete picture.
 */
export function useLiveFeed(
  enabled: boolean,
  max = 200,
  filters: { service?: string; action?: string; kind?: string } = {},
): LiveFeedState {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [dropped, setDropped] = useState(0);
  const sourceRef = useRef<EventSource | null>(null);
  const { service, action, kind } = filters;

  useEffect(() => {
    if (!enabled) {
      sourceRef.current?.close();
      sourceRef.current = null;
      setConnected(false);
      return;
    }
    const params = new URLSearchParams();
    if (service) params.set("service", service);
    if (action) params.set("action", action);
    if (kind) params.set("kind", kind);
    const url = `/api/v1/events/stream${params.toString() ? `?${params}` : ""}`;
    const es = new EventSource(url, { withCredentials: true });
    sourceRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("audit", (ev) => {
      try {
        const parsed = JSON.parse((ev as MessageEvent).data) as AuditEvent;
        setEvents((prev) => [parsed, ...prev].slice(0, max));
      } catch {
        // A malformed frame should not tear down the feed.
      }
    });
    es.addEventListener("dropped", (ev) => {
      try {
        const { dropped: n } = JSON.parse((ev as MessageEvent).data) as { dropped: number };
        setDropped((prev) => prev + n);
      } catch {
        /* ignore */
      }
    });

    return () => {
      es.close();
      sourceRef.current = null;
      setConnected(false);
    };
  }, [enabled, max, service, action, kind]);

  return { events, connected, dropped, clear: () => { setEvents([]); setDropped(0); } };
}
