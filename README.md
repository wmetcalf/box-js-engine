# box-js-engine

A [blastbox](https://github.com/wmetcalf/blastbox) engine that runs
[box-js](https://github.com/wmetcalf/box-js) on a JScript/JS sample and seals the IOCs
and dropped files it observed.

## Why a separate repo

blastbox ships no domain engines — they live in their own repos and plug in via
`BLASTBOX_ENGINE=module:Class` (ClippyShot, RedTusk, win-validator all work this way).
Keeping this out of the box-js fork also keeps that fork's job clean: it tracks
upstream `kirk-sayre-work/box-js`, and every directory added there is permanent merge
surface.

box-js is pinned here as a **git submodule**, so bumping the emulator is a deliberate,
reviewable act rather than drift. The image builds **from the fork**, never
`npm install box-js` — the public package lacks the fork's fixes.

## Isolation

vm2 is not the security boundary. It is an in-process JavaScript sandbox with a
documented escape history; the **disposable blastbox worker is the boundary**. This
engine does no isolation of its own and relies on the framework for pooling, warm/cold
tier selection, queue sizing, egress policy and output sealing.

`Limits.net_egress` chooses between box-js's `--download` and `--fake-download`, so the
emulator never fetches a live payload while the worker believes it is offline.

## Build

    git submodule update --init
    docker build -t boxjs-cold-worker:dev -f deploy/docker/Dockerfile.boxjs-cold-worker .
    docker build --build-arg BASE=boxjs-cold-worker:dev \
      --build-arg BLASTBOX_SRC=../blastbox \
      -f deploy/gvisor/Dockerfile.boxjs -t boxjs-warm:gvisor .

Warm needs `run_warm.py` and `engines.py` from a blastbox checkout (`BLASTBOX_SRC`);
they are deliberately not vendored.

## Is warm worth it?

Yes, measured on toolz2 (see the header of `deploy/gvisor/Dockerfile.boxjs`): node plus
the box-js module graph is ~91 ms, but creating the container is ~4.2 s, more than twice
the emulation itself. A resident warm sandbox turns a ~6 s cold job into a ~2 s one.

## Status

The cold image builds (with a build-time box-js smoke run) and runs on toolz2;
`tests/test_contract.py` detonates real samples (WScript and node droppers) through box-js
and checks them, and the harness's sealed `metadata.json`, against the contract.

## Engine contract

[`blastbox-engine.toml`](blastbox-engine.toml) states what the `boxjs` engine emits today: the
artifact families under `<sample>.results/` (the `analysis` JSON/log files, box-js's saved code
as `snippet`, and everything else as `dropped`), the versioned `record` payload's required fields, no detection codes, the gaps a consumer
must know about, and Loadout's mapper (`backend/loadout/boxjs.py:map_outputs`).
`tests/test_contract.py` checks real detonations (direct and through the harness's sealed
`metadata.json`) against it.

    python -m blastbox.contract.engine_contract validate blastbox-engine.toml
    python -m blastbox.contract.engine_contract check blastbox-engine.toml metadata.json

The checker is not in a released blastbox yet, so `tests/test_contract.py` skips there; run it
with `PYTHONPATH=<blastbox-checkout>/src`. The real-detonation tests also need node and an
installed submodule (`git submodule update --init && (cd box-js && npm ci --omit=dev)`) or
`BOXJS_RUN_JS`.
