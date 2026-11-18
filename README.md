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

**Unmeasured — do not assume.** box-js's per-sample cost is dominated by emulation and
the rewrite stage, neither of which pre-warms. Warm only avoids node startup plus the
box-js module graph. Measure a trivial sample against a real one before choosing the
tier; see the header of `deploy/gvisor/Dockerfile.boxjs`.

## Status

Scaffold. The engine compiles and is unit-tested; **neither image has been built and no
end-to-end detonation has been run.**

## Engine contract

[`blastbox-engine.toml`](blastbox-engine.toml) states what the `boxjs` engine emits today: the
artifact families under `<sample>.results/` (the `analysis` JSON/log files and everything else
as `dropped`), the `record` payload's required fields, no detection codes, the gaps a consumer
must know about, and Loadout's mapper (`backend/loadout/boxjs.py:map_outputs`).
`tests/test_contract.py` checks real detonations (direct and through the harness's sealed
`metadata.json`) against it.

    python -m blastbox.contract.engine_contract validate blastbox-engine.toml
    python -m blastbox.contract.engine_contract check blastbox-engine.toml metadata.json

The checker is not in a released blastbox yet, so `tests/test_contract.py` skips there; run it
with `PYTHONPATH=<blastbox-checkout>/src`. The real-detonation tests also need node and an
installed submodule (`git submodule update --init && (cd box-js && npm ci --omit=dev)`) or
`BOXJS_RUN_JS`.
