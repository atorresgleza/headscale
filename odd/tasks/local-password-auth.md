# Local password authentication for Headscale
Base: upstream v0.29.3 (`5aff68b5b9921db5ccb88013bb1740077ab872fb`); branch: `feature/local-password-auth`.
Status: T1 committed and published only to the user's fork branch; production deployment, upstream PR, and merge require separate decisions.

## Specs
S1. "la idea es la siguiente, haces loguin con tailscale client, ahi va un a peticion y llega al servidor,e ntonce sale el register de headscale con la key de la pc, en ese momento de enves de salirte la pagina de register ponerle un loguin y si tienes acceso osea si te autenticas puedes registrar la pc en headscale vajo el user que se registro. no se si tenemos que crear primero un invite user o algo asi"
S2. "primeramente un loguin comun y luego le agregamos un loguin auth con google"
S3. "Solo administrador (recomendado)"
S4. "Cambiar a recuperación por administrador"
S5. "Luego podremos edirar el register page para que se comporte como queremos. hacemos el build y lo montamos todo"
S6. "haber podemos usar el hosting para ello, sube los cambios a mi repositorio y seguimos el dev en el hosting que ya esta preparado para ello"
S7. "la idea es hacerlo como si lo fueramos a proponer pero mantenerlo como variante propia"
S8. "tenemos un apartado de user, puedes crear uno dentro, y le puedes asiganr un email, como no tenemos smtp todabia podriasmo agregar un link de invitacion, asi al enviarlo llegaria al register"
S9. "por ahora no cambies como funciona el user, lo que puedes hacer es invitar usando como funciona el user ahora mismo"
S10. "implementalos por favor"
S11. "continua por favor"
S12. "ok, no habia entendido que faltaba, haslo local pero usa docker por favor, necesitaras hacer el buil primero asi que prepara un docker composer para hacer el test"
S13. "Sí, probar actualización PostgreSQL (recomendado)"
S14. "agrega un renovar password en la parte de user, el problema que veo es que usan la key del user para todo, no deberia ser deberia usar el password"
S15. "Sí, contraseña para aprobar el dispositivo"
S16. "Sí, por etapas y con commits locales"
S17. "Pausar la generación"
S18. "es 4ADO esta en .ssh configurado y veras un folder headscale en la pc, aste uno propio en el home, el que tenemos arriba tiene toda la info"
S19. "estamso por remoto con 4ADO el headscale esta clonado en /home/adrian/code, puedes continuar"
S20. "continua"

## Tasks
T1 [S1-S4,S7-S13] route: done — persistence, PostgreSQL tests and independent verification passed; commit: `66ced180160fd1ff34f3825b1e692412bdbe6b47`; native review `review-578b060d213820b1` approved and acknowledged.
T2 [S1-S4,S7-S11,S14-S17,S19-S20] route: in progress — prepare the user-authorized Docker toolchain on 4ADO; implement administrator-issued invitation, password renewal and enrollment, with tests and staged commits. Do not expose public HTTP routes before security controls are in place; commit: pending.
T3 [S1-S4,S7-S11,S14-S15] route: pending — browser password login and one-shot pending-device confirmation; preserve device keys and AuthID; commit: pending.
T4 [S1-S12] route: pending — validate build, regressions, isolated end-to-end flow and docs; commit: pending.
T5 [S5-S7] route: blocked — separately authorize production migration/rollback and deployment; commit: pending.
T6 [S6] route: done — pushed `feature/local-password-auth` to the user's fork (push exit 0, branch observed on 4ADO); commit: `66ced180160fd1ff34f3825b1e692412bdbe6b47`.
T7 [S6,S18-S20] route: done — user-designated clean checkout `/home/adrian/code/headscale` switched to the feature branch at `66ced180`; `/home/adrian/headscale` remained untouched; commit: not applicable (checkout setup only).

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
L20. Docker rebuild and `docker compose -f compose.db-test.yml run --rm db-test` exited 0; `TestLocalInvitationPostgresUpgradePreservesExistingUser` and concurrent redemption both PASS (not SKIP), alongside SQLite cases. The isolated upgrade fixture preserves the preceding schema and user, then verifies public invitation/password behavior after reopening. Final independent verifier found no concrete T1 blocker; no tests were rerun by that verifier.
L21. User authorized staged local commits. T1 commit `66ced180160fd1ff34f3825b1e692412bdbe6b47` contains persistence, tests, design and Compose; native review `review-578b060d213820b1` approved and acknowledged. No deployment.
L22. "agrega un renovar password en la parte de user, el problema que veo es que usan la key del user para todo, no deberia ser deberia usar el password"
L23. `User` has no user key; `Node.MachineKey` and `Node.NodeKey` authenticate the device, while the pending `AuthID` identifies registration. Password must authenticate the human approver without replacing any of them.
L24. "Sí, contraseña para aprobar el dispositivo"
L25. "Sí, por etapas y con commits locales"
L26. T2 requires user RPCs, regenerated protobuf types, State/gRPC/CLI commands/help, secure enrollment, and tests. Before public HTTP, enforce HTTPS public origin, shared attempt limiting, CSRF, safe invitation-token handling, and generic errors. User approved staged commits, not a deployment.
L27. "Pausar la generación"
L28. Direct local Go/buf/protoc tooling was unavailable and the user paused Nix/Docker preparation locally. No T2 source edits were made before hosting continuation.
L29. "haber podemos usar el hosting para ello, sube los cambios a mi repositorio y seguimos el dev en el hosting que ya esta preparado para ello"
L30. Fork branch push exited 0 and created `feature/local-password-auth` at `66ced180`. A later GitHub read-back failed due network access; no upstream PR, merge or deployment.
L31. "es 4ADO esta en .ssh configurado y veras un folder headscale en la pc, aste uno propio en el home, el que tenemos arriba tiene toda la info"
L32. User authorized inspecting `/home` and `/home/adrian` and creating `/home/adrian/headscale-local-auth`, but declined reading `/home/adrian/headscale` and selected a direct fork clone. One guarded SSH clone failed before contacting the host (`No route to host`); its remote effects could not then be verified.
L33. "estamso por remoto con 4ADO el headscale esta clonado en /home/adrian/code, puedes continuar"
L34. The configured remote SSH tool found a clean clone at `/home/adrian/code/headscale`, initially on `main`; `origin/feature/local-password-auth` pointed at `66ced180`. Switched that checkout to a tracking local feature branch; verified clean status and HEAD. No files in `/home/adrian/headscale` were read or changed.
L35. "continua"
L36. On 4ADO, direct `go`, `buf`, and `protoc` are absent. Docker Engine 29.9.2 and Compose 5.6.0 respond; required Go/buf images are not cached. User explicitly authorized Docker on 4ADO for isolated generation/tests, including daemon images and cache, without deployment. Read `cmd/hi/README.md` and `integration/README.md` before generator/test work. The separate local task-log native review `review-1f2fe354e381aa5d` remains open after reviewer relay `fetch failed`; it supplies no approval for this remote change.
