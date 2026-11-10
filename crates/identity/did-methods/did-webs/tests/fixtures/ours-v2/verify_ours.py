"""Check that keripy accepts the whole `keri.cesr` this crate publishes.

`lifecycle.keri.cesr` is one did:webs identifier on KERI 2.0, written by this
crate's public API (`cargo run -p affinidi-did-webs --features create --example
emit_keripy_fixture`): created with designated aliases, key agreement, a
service and an endpoint; its key agreement replaced; rotated; and given a new
endpoint under the rotation's key state. `lifecycle.json` records what this
crate read from it. With keripy, this checks:

1. keripy parses the whole stream, starting in genus 1 as a resolver must (a
   stream with no genus counter is v1; ours opens with the v2 counter), and
   reaches the recorded KEL state;
2. keripy accepts the endpoint replies (`/end/role/add`, `/loc/scheme`) and
   reaches the recorded endpoint and location, the latest under the rotation;
3. for every designation: keripy's `SerderACDC` verifies the SAIDs, keripy's
   `messagize` frames each `rip` and `bup` exactly as the stream carries it,
   keripy's `Blinder` reproduces every BLID, and keripy's registry verifier
   (`keri.acdc.regeventing.vetBinds`), over the KEL keripy read, reaches the
   status this crate read.

keripy's parser does not route ACDC registry messages from a stream, so (3)
builds keripy's objects from the bodies `lifecycle.json` records, and checks
those bodies are the stream's.

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I verify_ours.py .

keripy version: affinidi-keri-rs, crates/affinidi-keri-core/tests/fixtures/keripy-v2/KERIPY_VERSION.
Exits non-zero on any disagreement.
"""

import json
import os
import sys

import keri
from keri import Vrsn_1_0
from keri.acdc.regeventing import vetBinds
from keri.core import Blinder, BlindState, Kevery, Parser, SealSource, SerderACDC, messagize, routing
from keri.db import openDB


def check(stream, spec):
    problems = []
    pre = spec["kel"]["prefix"]
    with openDB(name="ours-did-webs", temp=True) as db:
        rvy = routing.Revery(db=db)
        kvy = Kevery(db=db, lax=False, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rvy.rtr)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(stream), kvy=kvy, rvy=rvy)

        kever = kvy.kevers.get(pre)
        got = kever and (kever.sn, kever.serder.said)
        if got != (spec["kel"]["sn"], spec["kel"]["said"]):
            problems.append(f"KEL: keripy reached {got}, ours {spec['kel']['sn']}, {spec['kel']['said']}")
            return problems

        ends = [list(k) for k, v in db.ends.getTopItemIter() if v.allowed]
        locs = [[k[0], k[1], v.url] for k, v in db.locs.getTopItemIter()]
        if ends != spec["ends"]:
            problems.append(f"endpoints: keripy {ends}, ours {spec['ends']}")
        if locs != spec["locs"]:
            problems.append(f"locations: keripy {locs}, ours {spec['locs']}")

        for c in spec["credentials"]:
            rip = SerderACDC(raw=c["rip"]["raw"].encode(), verify=True)
            acdc = SerderACDC(raw=c["acm"]["raw"].encode(), verify=True)
            if rip.said != c["registry"]:
                problems.append(f"rip SAID {rip.said} != {c['registry']}")
            if acdc.said != c["credential"]:
                problems.append(f"acm SAID {acdc.said} != {c['credential']}")
            framed = messagize(rip, bonds=[SealSource(s=c["rip"]["anchor"]["sn"], d=c["rip"]["anchor"]["said"])])
            if bytes(framed) not in stream:
                problems.append(f"rip {rip.said} as keripy frames it is not in the stream")
            if acdc.raw not in stream:
                problems.append(f"acm {acdc.said} is not in the stream")

            bups, blinders = [], []
            for u in c["updates"]:
                bup = SerderACDC(raw=u["raw"].encode(), verify=True)
                d = u["disclosure"]
                bl = Blinder(crew=BlindState(d="", u=d["uuid"], td=d["acdc"], ts=d["state"]), makify=True)
                if bl.said != d["blid"] or bup.sad["b"] != bl.said:
                    problems.append(f"bup {bup.said}: keripy's BLID {bl.said}, ours {d['blid']}, named {bup.sad['b']}")
                framed = messagize(bup, bonds=[SealSource(s=u["anchor"]["sn"], d=u["anchor"]["said"]), bl.data])
                if bytes(framed) not in stream:
                    problems.append(f"bup {bup.said} as keripy frames it is not in the stream")
                bups.append(bup)
                blinders.append(bl)
            try:
                status = vetBinds(rip=rip, updates=bups, db=db, blinders=blinders, target=acdc.said,
                                  controller=pre, acdc=acdc).state
            except Exception as ex:
                status = f"error:{type(ex).__name__}: {ex}"
            if status != c["expect"]:
                problems.append(f"{c['schema']}: keripy's vetBinds says {status}, ours {c['expect']}")
    return problems


def main(d):
    print(f"keripy {keri.__version__}")
    names = sorted(f[: -len(".keri.cesr")] for f in os.listdir(d) if f.endswith(".keri.cesr"))
    failed = 0
    for name in names:
        with open(os.path.join(d, f"{name}.keri.cesr"), "rb") as f:
            stream = f.read()
        with open(os.path.join(d, f"{name}.json")) as f:
            spec = json.load(f)
        problems = check(stream, spec)
        statuses = ", ".join(c["expect"] for c in spec["credentials"])
        if problems:
            failed += 1
            print(f"FAIL {name}  {statuses}")
            for p in problems:
                print(f"       {p}")
        else:
            print(f"ok   {name}  KEL sn={spec['kel']['sn']}, {len(spec['ends'])} endpoint, "
                  f"{len(spec['locs'])} location, designations: {statuses}")
    print(f"{len(names) - failed}/{len(names)} agree")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
