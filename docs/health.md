# Probes: /livez, /readyz, /version, /metrics

Every Latere service serves the same four paths on its internal listener,
through [`health.Handler`](../health/). This is the fleet's decision; a
service adopts it when it is next touched, and a new service starts with
it.

| Path | Answers | Body | Who reads it |
|---|---|---|---|
| `GET /livez` | 200 while the process runs | `ok` | Kubernetes liveness: a failure restarts the container |
| `GET /readyz` | 200 when the process can serve, 503 when it cannot | `ok`, or `not ready: <check>: <error>` | Kubernetes readiness: a failure takes the replica out of rotation; a developer reads the body |
| `GET /version` | 200 | `{"version", "commit", "build_time"}` | The release smoke, which compares `version` with the tag |
| `GET /metrics` | 200, where the service has metrics | Prometheus text exposition | The scraper |

## Why two probes and not one

The fleet had five spellings (`healthz`, `health`, `live`, `ready`,
`livez`, `readyz`) and a single `healthz` on most of them. Kubernetes has
two probe semantics with two consequences: liveness failing means
*restart me*, readiness failing means *take me out of rotation*. One path
for both means one answer for both, and a dependency outage then restarts
a process that was fine and would have served again the moment the
dependency returned. Restarting also drops the in-flight requests the
readiness signal was there to protect.

So liveness checks nothing but that the process answers, and readiness
checks the dependencies. A check belongs on `/readyz` when its failure
should stop new traffic and on nothing when its failure should not.

## Registers

`/livez` and `/version` never carry an error text or a secret: they are
read by the kubelet and by the smoke. `/readyz` carries the failing
check's name and error in its body, in the developer register, because
the person reading it is asking why a replica left rotation.
`health.Checks` folds several checks into one readiness and names each
failure.

## Moving a service

1. Mount `health.Handler(health.Options{...})` on the internal listener,
   with `Ready` composed from `health.Checks` and `Metrics` where the
   service has a registry.
2. Set `LegacyHealthz: true` if a manifest still probes `/healthz`, and
   change the manifest to `/livez` and `/readyz` in the same release.
3. Drop `LegacyHealthz` in the release after.
