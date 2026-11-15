/** Every screen the shell can show. Shared so pages can navigate themselves. */
export type RouteKey =
  | "dashboard" | "incidents" | "incident" | "graph" | "events"
  | "import" | "evidence" | "rules" | "providers" | "reports" | "settings";
