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

    def build_sbom(self) -> dict:
        """Constructs the JSON SBOM and computes its digest."""
        sbom_data = {
            "spec_version": "1.4",
            "components": self._get_active_dependencies()
        }
        sbom_str = json.dumps(sbom_data, sort_keys=True)
        sbom_hash = hashlib.sha256(sbom_str.encode('utf-8')).hexdigest()
        
        return {
            "sbom": sbom_data,
            "sbom_hash": sbom_hash
        }

    def verify_sbom(self, sbom_dict: dict) -> tuple:
        """
        Parses components against cve_database.json
        Returns: (is_valid: bool, cve_violations: list)
        """
        if not os.path.exists(self.cve_db_path):
            return True, []

        with open(self.cve_db_path, "r") as f:
            cve_db = json.load(f)

        violations = []

        for comp in sbom_dict.get("components", []):
            name = comp.get("name")
            version = comp.get("version")

            if name in cve_db and version in cve_db[name]:
                cve_meta = cve_db[name][version]
                if cve_meta and cve_meta.get("severity") in ["HIGH", "CRITICAL"]:
                    violations.append({
                        "name": name,
                        "version": version,
                        "cve_id": cve_meta.get("cve_id"),
                        "severity": cve_meta.get("severity")
                    })

        # Return tuple determining install capability
        is_safe = len(violations) == 0
        return is_safe, violations
