# Disposable local-auth staging

`verify.sh` performs the existing in-network Traefik transport check with a self-signed certificate. It does not register a device.

`verify-client.sh` is a separate, single-run test of a **real Tailscale software client inside an isolated Docker container**. It never changes the Windows Tailscale client, public DNS, production Headscale/Traefik, existing service networks or volumes. It uses `hs.aaaagen.com` only as an alias for the disposable proxy on the internal `headscale-t4-isolated` network; it does **not** publish a host port. Before issuing any test invitation or calling Tailscale login it checks that the alias resolves only to the proxy's private IP and that its one-day test-CA-issued certificate validates. The test CA is mounted only into the disposable client/flow containers. The build reads the existing staging-only Go module cache **read-only**, writes its own cache under an ignored scratch directory, and disables module network fetches. All generated user credentials and bearer links remain in a private directory removed by the scoped cleanup; never paste them into logs or send them to a real user.

From a clean committed 4ADO feature checkout, with the existing cached images and at least 3 GiB free, create a fresh ignored run directory and launch once detached:

```bash
run_dir=$(mktemp -d "$PWD/ignored/client-t4.XXXXXXXX")
setsid nohup bash integration/local_auth_staging/verify-client.sh "$run_dir" \
  </dev/null >"$run_dir/launcher.log" 2>&1 &
printf 'Run directory: %s\n' "$run_dir"
```

`exit` and `cleanup.exit` are durable numeric codes; missing files mean unknown outcome. `revision`, `client-version`, and sanitized `preflight.log` survive. A run expects: invitation redeemed, real client pending with zero nodes after password login, exactly one node for the test user only after explicit approval, confirmation replay denied, and successful client login. The script removes only its two named clients, its Compose project and network, and its own scratch. Check resource absence independently; an exit file alone does not prove cleanup.

This is **not** a physical Windows-device test, public-PKI proof, production proxy/log audit, public invitation delivery, or Tailscale peer UDP/DERP-connectivity proof. The offline staging DERP map is intentionally not a real relay. Do not turn this into deployment or repeat a failed run without examining its bounded cause and obtaining a separate decision.
