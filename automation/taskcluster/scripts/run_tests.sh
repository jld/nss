#!/usr/bin/env bash

set -v -e -x

if [ $(id -u) = 0 ]; then
    # Switch compilers.
    GCC=${GCC_VERSION:-gcc-5}
    GXX=${GXX_VERSION:-g++-5}

    update-alternatives --set gcc "/usr/bin/$GCC"
    update-alternatives --set g++ "/usr/bin/$GXX"

    # Stupid Docker.
    echo "127.0.0.1 localhost.localdomain" >> /etc/hosts

    # Drop privileges by re-running this script.
    exec su worker $0
fi

# Fetch artifact(s) if needed.
if [ ! -d "dist" ]; then
    # FIXME: remove this before upstreaming.
    TC_BASE=${TASKCLUSTER_BASE:-https://queue.taskcluster.net/v1/task}
    artifacts=dist.tar.bz2
    if [ -n "$USE_GCOV" ]; then
        artifacts="$artifacts gcno.tar.bz2"
    fi
    for file in $artifacts; do
        curl --retry 3 -Lo $file \
            $TC_BASE/$TC_PARENT_TASK_ID/artifacts/public/$file
        tar xvjf $file
    done
fi

# Run tests.
cd nss/tests && ./all.sh

# Export coverage data.
cd && mkdir artifacts
if [ -n "$USE_GCOV" ]; then
    lcov --capture --directory nss | bzip2 > artifacts/lcov.info.bz2
fi
