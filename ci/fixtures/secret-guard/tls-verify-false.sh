#!/bin/sh
skopeo copy --src-tls-verify=false docker://a docker://b
