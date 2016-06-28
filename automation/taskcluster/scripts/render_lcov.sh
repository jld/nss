#!/usr/bin/env bash

set -v -e -x

if [ $(id -u) = 0 ]; then
    # Drop privileges by re-running this script.
    exec su worker $0
fi

# Fetch artifacts.
mkdir input
TC_BASE=${TASKCLUSTER_BASE:-https://queue.taskcluster.net/v1/task}
for id in $TC_PARENT_TASK_IDS; do
    # FIXME: pipelining?
    curl --retry 3 -Lo input/${id}.info.bz2 \
        $TC_BASE/$id/artifacts/public/lcov.info.bz2
done

# Uncompress.
bunzip2 input/*.info.bz2

# Build HTML.
# (FIXME: file a bug to fix those broken lex/yacc markers.)
DIRNAME=nss-lcov-html
genhtml --ignore-errors source --prefix $PWD/nss -o $DIRNAME input/*.info

# Export artifact.
mkdir artifacts
tar cvfj artifacts/${DIRNAME}.tar.bz2 $DIRNAME
