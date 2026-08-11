#!/usr/bin/env python3
"""Build the synthetic production publication only inside GitHub Actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from govp import authorize_subordinate_key, publication_entry_id, publish_request
from govp.envelope import sign_envelope
from govp.publication import event_descriptor

DOMAIN = "https://govp.io"
EVENT_TYPE = "org.govp.build/1"


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def event(
    key: Ed25519PrivateKey,
    identifier: str,
    created_at: str,
    subject: bytes,
) -> dict[str, object]:
    return sign_envelope(
        {
            "govp": "GOVP-EXT-1",
            "extension": {"id": "org.govp.publication", "version": "1.0.0"},
            "type": EVENT_TYPE,
            "id": identifier,
            "issuer": {
                "canonical": f"{DOMAIN}/.well-known/govp.txt",
                "name": "GOVP Protocol",
            },
            "subject": {"type": "ci-build", "id": identifier},
            "created_at": created_at,
            "hash": {"alg": "sha256", "value": hashlib.sha256(subject).hexdigest()},
            "payload": {
                "commit": os.environ["GITHUB_SHA"],
                "repository": os.environ["GITHUB_REPOSITORY"],
                "result": "pass",
                "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
            },
            "references": [],
            "evidence": [],
            "origin": {
                "origin": "system_observed",
                "observed_by": "govp.io publication workflow/1.0.0",
                "observation": {"run_id": os.environ["GITHUB_RUN_ID"]},
            },
        },
        key,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain-key", required=True, type=Path)
    parser.add_argument("--public-dir", required=True, type=Path)
    parser.add_argument("--custody-dir", required=True, type=Path)
    parser.add_argument("--export-proof", required=True, type=Path)
    arguments = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("publication demo can run only in GitHub Actions")

    source = Path(__file__).resolve().parents[1]
    workspace = arguments.public_dir.parent / "publication-input"
    workspace.mkdir(mode=0o700)
    shutil.copyfile(source / ".well-known/govp.txt", workspace / "govp.txt")
    shutil.copyfile(
        source / ".well-known/govp/revoked.json", workspace / "revoked.json"
    )
    shutil.copyfile(source / ".well-known/govp/index.json", workspace / "index.json")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    created_at = timestamp(now)
    subordinate = Ed25519PrivateKey.generate()
    subordinate_public = workspace / "subordinate-public.pem"
    subordinate_public.write_bytes(
        subordinate.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    authorization = workspace / "authorization.json"
    authorize_subordinate_key(
        domain=DOMAIN,
        domain_private_key=arguments.domain_key,
        subordinate_public_key=subordinate_public,
        allowed_types=[EVENT_TYPE],
        valid_from=timestamp(now - timedelta(minutes=1)),
        valid_until=timestamp(now + timedelta(hours=24)),
        output=authorization,
        created_at=created_at,
    )

    events: list[dict[str, str]] = []
    public_envelope: dict[str, object] | None = None
    run_id = os.environ["GITHUB_RUN_ID"]
    for disposition in ("publish", "sealed_private"):
        identifier = f"BUILD-{run_id}-{disposition.upper()}"
        subject = (
            f"Synthetic GOVP publication evidence\nrun={run_id}\ndisposition={disposition}\n"
        ).encode()
        envelope = event(subordinate, identifier, created_at, subject)
        envelope_name = f"{disposition}-event.json"
        subject_name = f"{disposition}-subject.bin"
        write_json(workspace / envelope_name, envelope)
        (workspace / subject_name).write_bytes(subject)
        events.append(
            {
                "disposition": disposition,
                "envelope": envelope_name,
                "subject": subject_name,
            }
        )
        if disposition == "publish":
            public_envelope = envelope

    request = {
        "authorization": authorization.name,
        "base_index": "index.json",
        "batch_id": f"GOVP-IO-{run_id}",
        "created_at": created_at,
        "domain": DOMAIN,
        "events": events,
        "identity_record": "govp.txt",
        "publish_types": [EVENT_TYPE],
        "schema": "org.govp.publish-request/1",
        "status": "revoked.json",
        "workload": {
            "refs": [os.environ["GITHUB_REF"]],
            "repository": os.environ["GITHUB_REPOSITORY"],
        },
    }
    request_path = workspace / "publish-request.json"
    write_json(request_path, request)
    output = publish_request(
        request_path=request_path,
        domain_private_key=arguments.domain_key,
        public_dir=arguments.public_dir,
        custody_dir=arguments.custody_dir,
    )
    if public_envelope is None or output.public_count != 1 or output.private_count != 1:
        raise SystemExit("publication output counts are invalid")
    entry_id = publication_entry_id(event_descriptor(public_envelope))
    arguments.export_proof.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        arguments.custody_dir / "proofs" / f"{entry_id}.json",
        arguments.export_proof,
    )
    print(
        json.dumps(
            {
                "batch_id": request["batch_id"],
                "entry_id": entry_id,
                "private_count": output.private_count,
                "public_count": output.public_count,
                "root": output.public_root,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
