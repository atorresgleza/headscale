# Local password authentication for Headscale
Base: upstream v0.29.3 (`5aff68b5b9921db5ccb88013bb1740077ab872fb`); branch: `feature/local-password-auth`.
Status: local development only; do not publish or deploy without a separate decision.

## Specs
S1. "la idea es la siguiente, haces loguin con tailscale client, ahi va un a peticion y llega al servidor,e ntonce sale el register de headscale con la key de la pc, en ese momento de enves de salirte la pagina de register ponerle un loguin y si tienes acceso osea si te autenticas puedes registrar la pc en headscale vajo el user que se registro. no se si tenemos que crear primero un invite user o algo asi"
S2. "primeramente un loguin comun y luego le agregamos un loguin auth con google"
S3. "Solo administrador (recomendado)"
S4. "Cambiar a recuperación por administrador"
S5. "Luego podremos edirar el register page para que se comporte como queremos. hacemos el build y lo montamos todo"
S6. "No publicar todavía"
S7. "la idea es hacerlo como si lo fueramos a proponer pero mantenerlo como variante propia"
S8. "tenemos un apartado de user, puedes crear uno dentro, y le puedes asiganr un email, como no tenemos smtp todabia podriasmo agregar un link de invitacion, asi al enviarlo llegaria al register"
S9. "por ahora no cambies como funciona el user, lo que puedes hacer es invitar usando como funciona el user ahora mismo"
S10. "implementalos por favor"
S11. "continua por favor"
S12. "ok, no habia entendido que faltaba, haslo local pero usa docker por favor, necesitaras hacer el buil primero asi que prepara un docker composer para hacer el test"
S13. "Sí, probar actualización PostgreSQL (recomendado)"

## Tasks
T1 [S1-S4,S7-S13] route: blocked — persistence, Docker tests and independent verification passed; waiting for authorization to make a local work-unit commit; commit: pending.
T2 [S1-S4,S7-S11] route: implement administrator-issued invitation and password enrollment interface with tests; commit: pending.
T3 [S1-S4,S7-S11] route: implement browser login and pending-device confirmation with tests; commit: pending.
T4 [S1-S12] route: validate local build, regression suite, isolated end-to-end flow and documentation; commit: pending.
T5 [S5-S7] route: separately authorize and prepare remote migration/rollback and deployment; commit: pending.

## Log
L1. "entonces lo que podemos hacer es descargarnos el repo en la pc local y hacer un fork del proyecto principal en github. Luego podremos edirar el register page para que se comporte como queremos. hacemos el build y lo montamos todo"
L2. User selected direct password authentication in Headscale fork over OIDC; administrator-created accounts; initially email self-service recovery, then changed to administrator-managed password recovery; no GitHub publication yet.
L3. Upstream v0.29.3 cloned locally at `/home/kino/work/headscale` on `feature/local-password-auth`; source tree was clean. No source changes or deployment.
L4. T1 worker refused its safe-root bootstrap twice (`original safe project root` and `repository preparation unavailable`); no source edits or tests were performed. Resume in a Pi session rooted at the clone.
L5. "la idea es hacerlo como si lo fueramos a proponer pero mantenerlo como variante propia"
L6. "continua con eso en mente"
L7. "tenemos un apartado de user, puedes crear uno dentro, y le puedes asiganr un email, como no tenemos smtp todabia podriasmo agregar un link de invitacion, asi al enviarlo llegaria al register"
L8. Architecture mapping: existing web registration is an administrator CLI approval page; OIDC has explicit one-shot device confirmation. The prior safe-root blocker is resolved in this session. No publication was authorized.
L9. Independent design review found that `User.Username()` prefers `Email` over `Name` (`hscontrol/types/users.go:115-127`); admin-assigned email could change policy identity. Also identified invitation URL logging, reset, rate limiting, password baseline and TLS proxy decisions. Design draft corrected; no implementation or tests yet.
L10. "por ahora no cambies como funciona el user, lo que puedes hacer es invitar usando como funciona el user ahora mismo"
L11. "implementalos por favor"
L12. "continua por favor"
L13. First implementation unit scoped to isolated invitation/credential persistence; HTTP exposure and operator CLI follow only after its security and regression checks.
L14. RED: `go test ./hscontrol/db -run '^TestLocalInvitation' -count=1` failed compiling missing Issue/Redeem/Verify APIs. GREEN: focused test and `go test ./hscontrol/db -count=1` passed before verifier corrections. Independent verifier requested explicit revocation, UTF-8 boundaries and PostgreSQL/race evidence. Follow-up RED compiling missing Revoke API; corrected implementation and tests. Focused `go test ./hscontrol/db -count=1 -v -run '^TestLocalInvitation'` passed SQLite cases, but PostgreSQL concurrent redemption SKIPPED: `initdb: executable file not found in $PATH`. Final package suite after corrections, PostgreSQL migration/race checks and final independent verification are pending. No CLI/HTTP exposure, commit, push or deployment.
L15. "ok, no habia entendido que faltaba, haslo local pero usa docker por favor, necesitaras hacer el buil primero asi que prepara un docker composer para hacer el test"
L16. `postgrestest` invokes `initdb` in the same process environment as Go tests; added `Dockerfile.db-test` and `compose.db-test.yml` to build and run the package test binary as unprivileged `postgres`.
L17. `docker compose -f compose.db-test.yml config --quiet` passed; Docker build exited 0 and `docker compose -f compose.db-test.yml run --rm db-test` exited 0 with all focused tests PASS, including `TestLocalInvitationPostgresConcurrentRedemption` (not SKIP). Post-correction `go test ./hscontrol/db -count=1` passed. A prematurely launched Compose run was stopped before the build completed; `docker ps` showed no test container; the later run used the completed build.
L18. Independent verifier found no persistence regression, but T1 is not fully verified: fresh PostgreSQL and replay were exercised, whereas upgrading a preexisting PostgreSQL schema through the new migration remains untested. Do not claim completion, publish, deploy or advance to public login yet; no commit.
L19. "Sí, probar actualización PostgreSQL (recomendado)"
L20. Docker rebuild and `docker compose -f compose.db-test.yml run --rm db-test` exited 0; `TestLocalInvitationPostgresUpgradePreservesExistingUser` and concurrent redemption both PASS (not SKIP), alongside SQLite cases. The isolated upgrade fixture preserves the preceding schema and user, then verifies public invitation/password behavior after reopening. Final independent verifier found no concrete T1 blocker; no tests were rerun by that verifier. Local work-unit commit awaits explicit user authorization; no push or deployment.
