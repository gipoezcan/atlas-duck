# atlas-duck-server container image (M12 T25; SM-1.3, SM-7.1, SM-9.1, PD-222).
#
# Build from the repository root:
#   docker build -f crates/server/Dockerfile -t atlas-duck-server:dev .
#
# Run locally against the test directory (crates/server/fixtures/test-directory.json: users
# alice, bob, carol-admin, dave-auditor; NOT for production, ATLAS_DUCK_MODE=production refuses it):
#   docker run --rm -p 8080:8080 --read-only --cap-drop ALL --security-opt no-new-privileges \
#     -e ATLAS_DUCK_MODE=dev -e ATLAS_DUCK_PUBLIC_URL=http://localhost:8080 \
#     -e ATLAS_DUCK_DATA_DIR=/data -e ATLAS_DUCK_MASTER_KEY_FILE=/run/secrets/master-key \
#     -e ATLAS_DUCK_TEST_DIRECTORY_FILE=/fixtures/test-directory.json \
#     -e GROUP_USERS=cn=atlas-duck-users,ou=groups,dc=test \
#     -e GROUP_ADMINS=cn=atlas-duck-admins,ou=groups,dc=test \
#     -e GROUP_AUDITORS=cn=atlas-duck-auditors,ou=groups,dc=test \
#     -v $PWD/data:/data -v $PWD/master-key:/run/secrets/master-key:ro \
#     -v $PWD/crates/server/fixtures:/fixtures:ro atlas-duck-server:dev
#
# The master key file holds one line `atlas-duck-master-key/v1 <id> <base64 of 32 bytes>`
# (ci/server-test-master-key.sh writes a throwaway one). No secret is ever an ENV or ARG here.
# Base images are pinned by tag; their digests are added from the first CI run's log.

FROM node:22.13.1-bookworm-slim AS ui
WORKDIR /src/app/ui
COPY app/ui/package.json app/ui/package-lock.json app/ui/.npmrc ./
RUN npm ci --ignore-scripts
COPY app/ui/ ./
RUN npm run build:server

FROM rust:1.95.0-bookworm AS build
# The image's own toolchain (rust-toolchain.toml names the same version but also every desktop
# target, which this build does not need).
ENV RUSTUP_TOOLCHAIN=1.95.0
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# A workspace member; copied only so the workspace resolves with --locked. The server's closure
# links no Tauri, so no GTK/WebKit packages are needed.
COPY app/src-tauri/ app/src-tauri/
# M14 T14 (PD-250): the sandbox worker beside the server (the desktop's `atlas-duck-sandbox` bin is
# a Tauri-package target; `atlas-duck-sandbox-worker` is the same thin main without Tauri).
RUN cargo build --release --locked -p atlas-duck-server -p atlas-duck-sandbox-worker \
      --bin atlas-duck-server --bin atlas-duck-sandbox-worker \
 && strip target/release/atlas-duck-server target/release/atlas-duck-sandbox-worker

# M14 T14: the M8 `confined_scripts` corpus as a test binary on the runtime image's base, for
# `ci/server-sandbox-container.sh` only (`docker build --target confined`; never pushed).
FROM build AS confined-build
RUN cargo test --locked -p atlas-duck-sandbox-worker --test confined_scripts --no-run \
 && exe="$(find target/debug/deps -maxdepth 1 -type f -name 'confined_scripts-*' -perm -u+x ! -name '*.d' | head -n 1)" \
 && test -n "$exe" && cp "$exe" /confined_scripts

FROM gcr.io/distroless/cc-debian12:nonroot AS confined
COPY --from=confined-build --chmod=0555 /confined_scripts /app/confined_scripts
USER 65532:65532
ENTRYPOINT ["/app/confined_scripts"]

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/atlas-duck-server /app/atlas-duck-server
# Owned by root, read-only and executable for the server user (PD-250: no capability, no setcap).
COPY --from=build --chmod=0555 /src/target/release/atlas-duck-sandbox-worker /app/atlas-duck-sandbox
COPY --from=ui /src/app/ui/dist-server/ /app/web/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/atlas-duck-server"]
CMD ["serve"]
