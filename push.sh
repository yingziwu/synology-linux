#!/bin/bash

LINUX_REPO_PATH=/srv/app/fork/synology-linux/linux

# Push branch
git -C $LINUX_REPO_PATH branch | grep -v -E "master|scripts" | xargs -n1 git -C $LINUX_REPO_PATH push -f origin

# Push base tag
jq -r ".[].base" resources/*.json | sort -u | xargs -n1 git -C $LINUX_REPO_PATH push -f origin