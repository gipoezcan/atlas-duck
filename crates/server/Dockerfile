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
# The one non-test include_str! input outside crates/ in the server's closure:
# crates/preview/src/sanitize.rs embeds the preview stylesheet.
COPY app/ui/public/preview.css app/ui/public/preview.css
# A workspace member; copied only so the workspace resolves with --locked. The server's closure
# links no Tauri, so no GTK/WebKit packages are needed.
COPY app/src-tauri/ app/src-tauri/
RUN cargo build --release --locked -p atlas-duck-server \
 && strip target/release/atlas-duck-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/atlas-duck-server /app/atlas-duck-server
COPY --from=ui /src/app/ui/dist-server/ /app/web/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/atlas-duck-server"]
CMD ["serve"]
