"""Verify and apply decision certificates: `decision-certificate.v1` to `v1.5`
(spec/decision-certificate.v1.md, spec/decision-certificate.v1.1.md to spec/decision-certificate.v1.5.md).

A port of the Rust crate in this repository's `rust/`, which is the reference: both must agree on
every conformance fixture. A certificate describes a measured process; it never promises an outcome.

    from decision_cert import loads, verify
    v = verify(loads(open("cert.json").read()), keys)   # keys: key id -> base64url public key
    v.id, v.threshold_for("north"), v.is_expired(now)

    # v1.2: monitor a window of use-time confidences without labels;
    # None for a case unscored or above `rule.cannot_tell_above`
    window = Histogram.of(v.confidence_bins(), confidences)
    shift_score(v.histogram_for("north"), window).p_value

    # apply the certificate's calibration map (v1.2 kinds: temperature, dr) to a case's raw scores
    v.confidence(raw_scores) >= v.threshold_for("north")

    # v1.3: the options the consumer automates, and the error of the answered cases among them
    v.automate_options(), v.automated_for("north")

    # v1.5: a certificate bound to a tenant, verified for the tenant the consumer expects, against that
    # tenant's moded keys (a bare string entry is an operator key)
    v = verify_for_tenant(cert, "acme-bank", tenant_keys_from_json(tenant_keys))
    v.tenant(), v.signer()

    # an evidence pack (docs/evidence-pack.md): manifest, signatures, measured cases, recompute
    report = verify_pack(Path("pack/"), keys)
    report.ok, [(c.name, c.status) for c in report.checks]

    # inclusion v1 (spec/decision-cert-inclusion.v1.md): a bundle checked offline against a
    # tenant's log trust configuration; raises InclusionError with the error name (e.name) on refusal
    trust = LogTrust.from_json(parse_ijson(open("log-trust.json").read()))
    verdict = verify_bundle(parse_ijson(open("bundle.json").read()), trust)
    verdict.t_proven_time(), verdict.to_json()
    verdict.backfilled, verdict.backfilled_by           # a certificate leaf's backfilled mark (§10)

    # the issuer's side: a certificate's leaf record for the tenant's log, the backfill of older
    # certificates (§12), and the bundle once a cosigned checkpoint includes the leaf
    leaf_record(cert)                                   # {"certificate_id", "leaf", "leaf_hash"}
    bundle, verdict = bundle_certificate(cert, leaf_index, proof, checkpoint_text, trust)
    backfill_records(certs, tenant)                     # records with "backfilled": true, leaves unchanged

    # the reference log and witness (plan Phase 5): one tenant's log in a directory, C2SP tlog-tiles
    log = FileLog.init(path, tenant, log_public_key)    # or FileLog(path) for an existing one
    log.append(records, now); log.checkpoint(log_private_key, now); log.prove(checkpoint_text, index)
    FileWitness(state_path).cosign(checkpoint_text, consistency_doc, witness_private_key, now)
"""

from ._bundle import (
    NotYetInCheckpoint,
    backfill_order,
    backfill_records,
    bundle_bytes,
    bundle_certificate,
    certificate_leaf,
    leaf_record,
    leaf_records_text,
)
from ._inclusion import (
    ConsistencyVerdict,
    CountedWitness,
    ErrorName,
    InclusionError,
    InclusionVerdict,
    Leaf,
    LogTrust,
    Policy,
    PolicyOutcome,
    apply_policy,
    check_tenants,
    leaf_hash,
    parse_checkpoint,
    parse_ijson,
    verify_bundle,
    verify_consistency,
)
from ._log import (
    FileLog,
    FileWitness,
    LogError,
    NotIncludedYet,
    cosignature_line,
    log_signature_line,
    trust_config,
)
from ._map import MAP_KINDS, confidence, probabilities
from ._monitor import Histogram, ShiftScore, bin_of, chi2_sf, shift_score
from ._pack import PACK_FORMAT, Check, Limits, PackError, PackReport, measured_cases_hash, verify_pack
from ._verify import (
    ABSTAIN_ALL,
    SPEC,
    SPEC_V1_1,
    SPEC_V1_2,
    SPEC_V1_3,
    SPEC_V1_4,
    SPEC_V1_5,
    SPECS,
    V1_2_FIELDS,
    V1_3_FIELDS,
    V1_5_FIELDS,
    BadKey,
    BadSignature,
    CertError,
    Invalid,
    KeyMode,
    TrustedKey,
    UntrustedKey,
    Verified,
    WrongTenant,
    canonical,
    certificate_id,
    is_expired,
    key_id,
    loads,
    signed_bytes_v1_5,
    tenant_keys_from_json,
    threshold_for,
    timestamp,
    verify,
    verify_for_tenant,
)

__version__ = "0.7.0"

__all__ = [
    "ABSTAIN_ALL",
    "MAP_KINDS",
    "PACK_FORMAT",
    "SPEC",
    "SPECS",
    "SPEC_V1_1",
    "SPEC_V1_2",
    "SPEC_V1_3",
    "SPEC_V1_4",
    "SPEC_V1_5",
    "V1_2_FIELDS",
    "V1_3_FIELDS",
    "V1_5_FIELDS",
    "BadKey",
    "BadSignature",
    "CertError",
    "Check",
    "ConsistencyVerdict",
    "CountedWitness",
    "ErrorName",
    "FileLog",
    "FileWitness",
    "Histogram",
    "InclusionError",
    "InclusionVerdict",
    "Invalid",
    "KeyMode",
    "Leaf",
    "Limits",
    "LogError",
    "LogTrust",
    "NotIncludedYet",
    "NotYetInCheckpoint",
    "PackError",
    "PackReport",
    "Policy",
    "PolicyOutcome",
    "ShiftScore",
    "TrustedKey",
    "UntrustedKey",
    "Verified",
    "WrongTenant",
    "__version__",
    "apply_policy",
    "backfill_order",
    "backfill_records",
    "bin_of",
    "bundle_bytes",
    "bundle_certificate",
    "canonical",
    "certificate_id",
    "certificate_leaf",
    "check_tenants",
    "chi2_sf",
    "confidence",
    "cosignature_line",
    "is_expired",
    "key_id",
    "leaf_hash",
    "leaf_record",
    "leaf_records_text",
    "loads",
    "log_signature_line",
    "measured_cases_hash",
    "parse_checkpoint",
    "parse_ijson",
    "probabilities",
    "shift_score",
    "signed_bytes_v1_5",
    "tenant_keys_from_json",
    "threshold_for",
    "timestamp",
    "trust_config",
    "verify",
    "verify_bundle",
    "verify_consistency",
    "verify_for_tenant",
    "verify_pack",
]
