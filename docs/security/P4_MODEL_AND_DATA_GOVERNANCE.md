# P4 model and labelled-data governance

P4 must not report detection quality unless `tests/phase4/model-governance.py`
passes before the evaluation run. Model binaries and candidate media are never
committed to this repository.

The operator supplies two external JSON manifests:

- `EXAMOS_VISION_MODEL_MANIFEST`: `examos-p4-model-manifest-v1`, containing
  each model's immutable ID, version, SHA-256, SPDX licence identifier,
  licence-file path, artifact path, and explicit commercial-use and
  redistribution approvals.
- `EXAMOS_VISION_DATASET_GOVERNANCE_MANIFEST`:
  `examos-p4-dataset-governance-v1`, containing the dataset identity/version,
  consent basis, permitted uses, retention/deletion process, annotation and
  label protocol, disjoint train/validation/test process, privacy owner,
  labelled-media manifest path, and `human_review_required: true`.

The gate validates that every model artifact matches its declared hash and
that every licence and media-manifest path exists. It does not accept missing
files, implicit commercial rights, implicit redistribution rights, invented
consent, or a quality metric without governance evidence.

Before any production evaluation, the privacy owner must approve consent and
permitted use, the model owner must approve licensing, and the evaluation
report must include false-positive/false-negative rates, subgroup limitations,
and the human-review/appeal procedure. Absence of any input is `BLOCKED`, not
`PASS`.
