import json
import hashlib
import os

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Software Bill of Materials (SBOM) allows exact auditing of
# third-party dependencies shipped in firmware.
# This realistic implementation maps a dynamic component payload
# against a local JSON vulnerability database. If high severity
# matches execute, the deployment policy halts installation.
# ---------------------------------------------------------

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BLOCKING_SEVERITIES = ("HIGH", "CRITICAL")


def _cve_db_problem(db):
    """None if `db` is {component: {version: {"cve_id": str, "severity": one of SEVERITIES}}}, else what is wrong.
    Every entry is checked before any lookup, so a bad record can't crash the scan past the gate."""
    if not isinstance(db, dict) or not db:
        return "top level must be a non-empty {component: {version: entry}} mapping"
    for name, versions in db.items():
        if not isinstance(versions, dict) or not versions:
            return f"{name!r}: expected a non-empty {{version: entry}} mapping"
        for version, entry in versions.items():
            if not version.strip():
                return f"{name!r}: empty version key"
            if not isinstance(entry, dict):
                return f"{name!r} {version!r}: entry must be an object, got {type(entry).__name__}"
            if not isinstance(entry.get("cve_id"), str) or not entry["cve_id"]:
                return f"{name!r} {version!r}: missing cve_id"
            if entry.get("severity") not in SEVERITIES:
                return f"{name!r} {version!r}: severity {entry.get('severity')!r} not one of {SEVERITIES}"
    return None


class SBOMScanError(ValueError):
    """The SBOM could not be scanned reliably; `reason` is the rejection code for the gateway."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class SBOMGenerator:
    def __init__(self):
        self.cve_db_path = os.path.join(os.path.dirname(__file__), "cve_database.json")

    def _get_active_dependencies(self) -> list:
        """
        In a real pipeline, Trivy or Syft tools extract this physically
        from the built firmware rootfs. For demo purposes, we formulate the stack here.
        """
        # A perfectly secure pipeline deployment (v8.4.0 is fully patched)
        deps = [
            {"name": "libc", "version": "1.0.4", "hash": hashlib.sha256(b"libc").hexdigest()},
            {"name": "openssl", "version": "3.0.8", "hash": hashlib.sha256(b"ssl").hexdigest()},
            {"name": "sqlite", "version": "3.42.0", "hash": hashlib.sha256(b"sqlite").hexdigest()},
            {"name": "libcurl", "version": "8.4.0", "hash": hashlib.sha256(b"libcurl").hexdigest()}
        ]

        # ATTACK VECTOR: If FORCE_CVE is flagged, the CI/CD pipeline acts compromised 
        # and quietly sneaks a vulnerable legacy version into the build.
        if os.environ.get("FORCE_CVE", "false").lower() == "true":
            for d in deps:
                if d["name"] == "libcurl":
                    d["version"] = "7.88.1" # Explicitly matches CVE-2023-38545

        return deps

    @staticmethod
    def compute_hash(sbom_data: dict) -> str:
        """Canonical SBOM digest: SHA-256 over json.dumps(sort_keys=True). Builder and ECU must both use this."""
        return hashlib.sha256(json.dumps(sbom_data, sort_keys=True).encode('utf-8')).hexdigest()

    def build_sbom(self) -> dict:
        """Constructs the JSON SBOM and computes its digest."""
        sbom_data = {
            "spec_version": "1.4",
            "components": self._get_active_dependencies()
        }
        sbom_hash = self.compute_hash(sbom_data)
        
        return {
            "sbom": sbom_data,
            "sbom_hash": sbom_hash
        }

    def verify_sbom(self, sbom_dict: dict) -> tuple:
        """
        Parses components against cve_database.json
        Returns: (is_valid: bool, cve_violations: list)
        Raises SBOMScanError when the scan cannot be trusted (no usable CVE database, or an
        SBOM without a well-formed component list), so the caller rejects instead of passing.
        """
        try:
            with open(self.cve_db_path, "r") as f:
                cve_db = json.load(f)
        except (OSError, ValueError) as e:
            raise SBOMScanError("SBOM_SCAN_UNAVAILABLE", f"CVE database unavailable: {e}") from e
        problem = _cve_db_problem(cve_db)
        if problem:
            raise SBOMScanError("SBOM_SCAN_UNAVAILABLE", f"CVE database malformed: {problem}")

        components = sbom_dict.get("components")
        if not isinstance(components, list) or not components:
            raise SBOMScanError("SBOM_MALFORMED", "SBOM has no component list")
        for comp in components:
            if not (isinstance(comp, dict) and isinstance(comp.get("name"), str) and isinstance(comp.get("version"), str)):
                raise SBOMScanError("SBOM_MALFORMED", f"SBOM component without string name/version: {comp!r:.80}")

        violations = []

        for comp in components:
            name = comp.get("name")
            version = comp.get("version")

            if name in cve_db and version in cve_db[name]:
                cve_meta = cve_db[name][version]
                if cve_meta["severity"] in BLOCKING_SEVERITIES:
                    violations.append({
                        "name": name,
                        "version": version,
                        "cve_id": cve_meta.get("cve_id"),
                        "severity": cve_meta.get("severity")
                    })

        # Return tuple determining install capability
        is_safe = len(violations) == 0
        return is_safe, violations
