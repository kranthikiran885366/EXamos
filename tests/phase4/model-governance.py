#!/usr/bin/env python3
"""Fail-closed provenance gate for P4 models and labelled evaluation data.

No model binary, licence text, media, or personal data belongs in this source
tree.  Operators provide two external JSON manifests and this gate verifies
their declared identities, content hashes and the approved use constraints
before any quality evaluator is allowed to run.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(errors):
    print(json.dumps({"phase": "P4", "test_suite": "model_dataset_governance",
                      "status": "BLOCKED", "errors": errors}, indent=2))
    return 2


def main():
    model_path = os.environ.get("EXAMOS_VISION_MODEL_MANIFEST")
    dataset_path = os.environ.get("EXAMOS_VISION_DATASET_GOVERNANCE_MANIFEST")
    if not model_path or not dataset_path:
        return fail(["set EXAMOS_VISION_MODEL_MANIFEST and EXAMOS_VISION_DATASET_GOVERNANCE_MANIFEST"])
    try:
        models = load(Path(model_path))
        dataset = load(Path(dataset_path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return fail([f"cannot read governance manifest: {exc}"])

    errors = []
    if models.get("schema") != "examos-p4-model-manifest-v1":
        errors.append("unsupported model manifest schema")
    entries = models.get("models")
    if not isinstance(entries, list) or not entries:
        errors.append("model manifest needs at least one pinned model")
    else:
        for index, item in enumerate(entries):
            required = ("id", "version", "sha256", "license_spdx", "license_file",
                        "artifact", "commercial_use_approved", "redistribution_approved")
            if not isinstance(item, dict) or any(not item.get(key) for key in required):
                errors.append(f"model[{index}] missing identity, licence, artifact, or approval")
                continue
            artifact, license_file = Path(item["artifact"]), Path(item["license_file"])
            if not SHA256.fullmatch(item["sha256"]):
                errors.append(f"model[{index}] SHA-256 is invalid")
            elif not artifact.is_file() or digest(artifact) != item["sha256"]:
                errors.append(f"model[{index}] artifact missing or hash mismatch")
            if not license_file.is_file():
                errors.append(f"model[{index}] licence file unavailable")
            if item["commercial_use_approved"] is not True or item["redistribution_approved"] is not True:
                errors.append(f"model[{index}] usage/redistribution approval is not explicit")

    required_dataset = ("dataset_id", "version", "consent_basis", "permitted_uses",
                        "retention_policy", "deletion_process", "annotation_protocol",
                        "label_schema", "train_validation_test_separation",
                        "privacy_owner", "human_review_required", "manifest")
    if dataset.get("schema") != "examos-p4-dataset-governance-v1":
        errors.append("unsupported dataset governance schema")
    for key in required_dataset:
        if not dataset.get(key):
            errors.append(f"dataset governance missing {key}")
    if dataset.get("human_review_required") is not True:
        errors.append("dataset governance must require human review for consequential decisions")
    labels = Path(dataset.get("manifest", ""))
    if labels and not labels.is_file():
        errors.append("authorised labelled-media manifest is unavailable")

    if errors:
        return fail(errors)
    print(json.dumps({"phase": "P4", "test_suite": "model_dataset_governance",
                      "status": "PASS", "model_count": len(entries),
                      "dataset_id": dataset["dataset_id"], "human_review_required": True}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
