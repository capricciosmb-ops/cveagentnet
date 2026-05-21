#!/usr/bin/env bash
# Convenience wrapper around docker compose for CVEAgentNet.
#
#   ./run.sh -start  [dev|prod]
#   ./run.sh -stop   [dev|prod]
#   ./run.sh -status [dev|prod]
#   ./run.sh -logs   [dev|prod] [service]
#
# dev (default) uses docker-compose.yml.
# prod uses docker-compose.prod.yml with .env.production.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: ./run.sh -start|-stop|-status|-logs [dev|prod] [service]

  -start  [dev|prod]            Build and start the stack, then wait for /health.
  -stop   [dev|prod]            Stop the stack.
  -status [dev|prod]            Show docker compose ps for the stack.
  -logs   [dev|prod] [service]  Follow logs (all services if no service given).

The first positional argument selects the action. The second selects the mode
and defaults to 'dev'. Prod mode reads .env.production.
EOF
  exit 2
}

action="${1:-}"
mode="${2:-dev}"

case "$mode" in
  dev)
    compose=(docker compose)
    health_url="http://localhost:8000/health"
    ;;
  prod)
    if [[ ! -f .env.production ]]; then
      echo "error: .env.production is required for prod mode (copy from .env.production.example)" >&2
      exit 1
    fi
    compose=(docker compose --env-file .env.production -f docker-compose.prod.yml)
    # In prod the API is internal; Caddy serves it. Probe through the api container.
    health_url=""
    ;;
  *)
    usage
    ;;
esac

wait_for_health() {
  # Best-effort readiness probe. 60 attempts × 2s = 120s max.
  local attempts=60
  while (( attempts-- > 0 )); do
    if [[ -n "$health_url" ]]; then
      if curl -fsS "$health_url" >/dev/null 2>&1; then
        echo "api is healthy"
        return 0
      fi
    else
      if "${compose[@]}" exec -T api curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
        echo "api is healthy"
        return 0
      fi
    fi
    sleep 2
  done
  echo "warning: api did not report healthy within 120s; run './run.sh -logs $mode api' to investigate" >&2
  return 1
}

case "$action" in
  -start)
    "${compose[@]}" up -d --build
    wait_for_health || true
    "${compose[@]}" ps
    ;;
  -stop)
    "${compose[@]}" down
    ;;
  -status)
    "${compose[@]}" ps
    ;;
  -logs)
    service="${3:-}"
    if [[ -n "$service" ]]; then
      "${compose[@]}" logs -f --tail=200 "$service"
    else
      "${compose[@]}" logs -f --tail=200
    fi
    ;;
  *)
    usage
    ;;
esac
