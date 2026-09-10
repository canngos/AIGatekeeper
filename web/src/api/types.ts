// Mirrors the JSON produced by internal/admin and internal/audit.

export type Action = "allow" | "block" | "monitor";

export interface Finding {
  detector: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  segment: string;
  role?: string;
  preview: string;
}

export interface AuditEvent {
  id?: number;
  ts: string;
  kind: string;
  request_id?: string;
  client_ip?: string;
  user?: string;
  device?: string;
  listener?: string;
  method?: string;
  host?: string;
  path?: string;
  service?: string;
  model?: string;
  stream?: boolean;
  action?: Action;
  block_mode?: string;
  reason?: string;
  rule?: string;
  findings?: Finding[];
  /** Present only when audit.capture_prompts is on. */
  prompt?: { path: string; role?: string; text: string }[];
  bytes_in?: number;
  bytes_out?: number;
  encoding?: string;
  upstream_status?: number;
  latency_ms: number;
  error?: string;
  message?: string;
}

export interface EventsPage {
  items: AuditEvent[];
  next_cursor?: string;
}

export interface Count {
  key: string;
  count: number;
}

export interface Summary {
  from: string;
  to: string;
  total: number;
  by_action: Count[] | null;
  by_service: Count[] | null;
  by_rule: Count[] | null;
  by_detector: Count[] | null;
  top_clients: Count[] | null;
  top_users: Count[] | null;
  top_hosts: Count[] | null;
  tunnel_events: number;
}

export interface Bucket {
  ts: string;
  group: string;
  count: number;
}

export interface Timeseries {
  from: string;
  to: string;
  bucket: string;
  series: Bucket[];
}

export interface Session {
  authenticated: boolean;
  method?: string;
  auth_configured: boolean;
  ui_built: boolean;
  version: string;
  expires_at?: string;
  csrf_token?: string;
}

export interface Status {
  version: string;
  uptime_seconds: number;
  listeners: Record<string, string>;
  ui_built: boolean;
  history: boolean;
  reload?: { reloads: number; failures: number; last_error: string; path: string };
  policy?: {
    version: string;
    loaded_at: string;
    source: string;
    monitor: boolean;
    services: number;
    rules: number;
    tunnel_unmatched: boolean;
  };
  audit_sinks?: { name: string; queued: number; dropped: number; written: number }[];
  history_store?: { written: number; errors: number; last_error: string };
  open_alerts?: number;
  identity?: {
    proxy_auth: boolean;
    reverse_dns: boolean;
    directory: boolean;
    proxy_auth_stats?: Record<string, number>;
  };
  alerts?: { rules: number; raised: number; suppressed: number };
}

/** One tunable of a detector, described by the server so the console can
    render a control for it without knowing the detector. */
export interface DetectorOption {
  name: string;
  label?: string;
  type: "bool" | "number" | "string" | "prefix_list";
  default: unknown;
  description: string;
}

export interface DetectorInfo {
  id: string;
  /** Short human label, e.g. "Cloud access key IDs". */
  name: string;
  /** Presentation group, e.g. "Keys and tokens". */
  group: string;
  description: string;
  severity: string;
  options?: DetectorOption[];
  /** Kept working for existing policies, but no longer offered. */
  deprecated?: boolean;
  replaced_by?: string;
}

/** A vendor prefix for the access_keys detector. A blank length means the
    detector's own min/max range applies. */
export interface AccessKeyPrefix {
  prefix: string;
  length?: number;
  note?: string;
}

export interface Problem {
  path: string;
  message: string;
}

// The configuration document, mirroring aigatekeeper.yaml. Only the parts
// the form editor touches are typed; everything else is preserved as-is.
export interface ServiceConfig {
  name: string;
  hosts: string[];
  extractor: string;
  block_mode: "reject" | "synthetic";
  passthrough_paths?: string[] | null;
  rules?: string[] | null;
}

export interface RuleConfig {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  action?: "block" | "monitor" | "allow";
  detectors?: string[] | null;
  keywords?: { file?: string; list?: string[] | null; case_insensitive?: boolean; word_boundary?: boolean };
  regex?: { id: string; pattern: string; min_length?: number }[] | null;
  options?: Record<string, Record<string, unknown>>;
}

export interface AllowlistConfig {
  values?: string[] | null;
  patterns?: string[] | null;
  email_domains?: string[] | null;
  client_cidrs?: string[] | null;
  header_bypass?: { name: string; token: string };
  segment_paths?: string[] | null;
}

export interface ConfigDoc {
  version: number;
  services: ServiceConfig[];
  rules: RuleConfig[];
  allowlist?: AllowlistConfig;
  mode?: { monitor: boolean };
  default_action?: string;
  block_message?: string;
  [key: string]: unknown;
}

export interface ConfigResponse {
  yaml: string;
  config: ConfigDoc;
  version: string;
  loaded_at: string;
  source: string;
  path: string;
}

export interface ValidateResponse {
  ok: boolean;
  errors: Problem[];
  yaml: string;
  config?: ConfigDoc;
  version?: string;
}

export interface Extraction {
  extractor: string;
  model?: string;
  stream: boolean;
  segments: { path: string; role?: string; text: string }[];
}

export interface TestResponse {
  extraction: Extraction;
  findings: Finding[];
  decision: { action: Action; rule: string; reason: string; block_mode: string; detectors: string[] };
  service: string;
  warning?: string;
}

export interface UserSummary {
  user?: string;
  device?: string;
  client_ip?: string;
  requests: number;
  blocked: number;
  flagged: number;
  last_seen: string;
}

export interface UsersResponse {
  users: UserSummary[];
  from: string;
  to: string;
  /** True when proxy authentication names people rather than machines. */
  attributed: boolean;
}

export interface AlertEventSummary {
  ts: string;
  request_id: string;
  service: string;
  host: string;
  path: string;
  action: string;
  rule: string;
  detectors: string[];
  previews: string[];
}

export interface AlertDetail {
  events?: AlertEventSummary[];
  detectors?: string[];
  services?: string[];
  notified?: string[];
  notify_errors?: string[];
  email?: string;
  manager?: string;
}

export interface StoredAlert {
  id: number;
  ts: string;
  rule_id: string;
  group_key: string;
  group_by: string;
  user?: string;
  device?: string;
  client_ip?: string;
  count: number;
  window: string;
  since: string;
  severity: string;
  status: "open" | "acknowledged";
  acknowledged_by?: string;
  acknowledged_at?: string;
  detail?: AlertDetail;
}

export interface AlertsResponse {
  items: StoredAlert[];
  next_cursor?: string;
  open: number;
  rules: string[];
}

export interface AlertTestResult {
  notifier: string;
  recipients?: string[];
  error?: string;
}
