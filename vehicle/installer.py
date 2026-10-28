from common.models import UpdateRequest
from common.logger import SecurityLogger
import os
import json
import time

# ---------------------------------------------------------
# SECURITY RATIONALE:
# ISO 26262 Functional Safety dictates that cyber-physical systems
# must not be interrupted during critical operations.
# The Installer implements strict safety interlocks.
# If an installation fails, the "Golden Image Rollback" mechanism
# atomically restores the ECU to its last known-good state.
#
# It also persists which build is currently installed (golden_image_build)
# across process restarts, so the Gateway ECU can detect a rollback/freeze
# attack -- an old, VALIDLY-signed manifest being replayed -- by comparing
# a candidate manifest's build_number against this record, independent of
# signature verification (which such a replayed manifest would still pass).
# ---------------------------------------------------------

class ECUInstaller:
    def __init__(self, device_id: str, logger: SecurityLogger):
        self.device_id = device_id
        self.logger = logger
        self.state_file = os.path.join("output", f"installed_state_{device_id}.json")
        self.golden_image_ver, self.golden_image_build, self.active_partition = self._load_state()
        self.inactive_partition = "SLOT_B" if self.active_partition == "SLOT_A" else "SLOT_A"

    def _load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    s = json.load(f)
                return s.get("version", "v1.0.0"), s.get("build_number", 1), s.get("active_partition", "SLOT_A")
            except (json.JSONDecodeError, OSError):
                pass
        return "v1.0.0", 1, "SLOT_A"  # Factory default golden image in Slot A

    def _save_state(self):
        os.makedirs("output", exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump({
                "version": self.golden_image_ver,
                "build_number": self.golden_image_build,
                "active_partition": self.active_partition
            }, f)

    def execute_install(self, target_version: str, target_build: int, state: UpdateRequest, payload: bytes = None) -> bool:
        """
        Safety constraints (all must hold before flashing):
        - state.battery_level MUST be >= 50
        - state.engine_state MUST be IDLE
        - state.gear_state MUST be PARK
        """
        self.logger.info("Evaluating safety interlocks for install...", device_id=self.device_id)

        if state.battery_level < 50.0:
            self.logger.warning("Installation blocked: Battery below 50%", event_type="safety_block", device_id=self.device_id)
            return False

        if state.engine_state != "IDLE":
            self.logger.warning(f"Installation blocked: Engine state is {state.engine_state}, must be IDLE", event_type="safety_block", device_id=self.device_id)
            return False

        if state.gear_state != "PARK":
            self.logger.warning(f"Installation blocked: Gear state is {state.gear_state}, must be PARK", event_type="safety_block", device_id=self.device_id)
            return False

        # Simulate Flash Write to Inactive Partition (Slot B)
        self.logger.info(f"Writing validated payload to Inactive Partition ({self.inactive_partition})...", device_id=self.device_id)
        
        if payload:
            self.logger.info(f"In-memory verification passed for {len(payload)} bytes. Output file materialization disabled.", device_id=self.device_id)

        # Atomic A/B Swap
        old_slot = self.active_partition
        self.active_partition = self.inactive_partition
        self.inactive_partition = old_slot
        self.golden_image_ver = target_version
        self.golden_image_build = target_build
        self._save_state()
        
        self.logger.info(
            f"Atomic A/B Partition Swap: Bootloader pointing to {self.active_partition}. Installation complete.",
            event_type="install_success",
            device_id=self.device_id
        )
        return True

    def rollback(self, reason: str = "HASH/SIGNATURE_FAILURE"):
        """Restores the Golden Image and wipes inactive slot."""
        self.logger.error(f"Performing automatic rollback to Golden Image: {self.golden_image_ver} on {self.active_partition}")
        self.logger.warning(f"Wiping {self.inactive_partition} header to prevent corrupted bootloader execution.")
        self.logger.error(f"ROLLBACK_TRIGGERED — reason: {reason} — golden image restored on {self.active_partition}", event_type="rollback", device_id=self.device_id)
        self.logger.info(f"Rollback successful. ECU state restored safely with zero vehicle downtime.", device_id=self.device_id)
