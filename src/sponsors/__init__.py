"""
AutoQrypt - Sponsor Integrations
Tier 1: QpiAI QCloud (Quantum Entropy & QRNG Seeding)
Tier 2: Bloq Platform (Quantum Crypto-Agility & Hardware Constrained Optimization)
"""

from .qpiai_qcloud import QpiAIEntropyEngine, QpiAIEntropyReceipt, QpiAIShorThreatReceipt, ensure_qpiai_local_auth
from .bloq_platform import BloqCryptoAgilityOptimizer, ECUAssignment, ECUQAOAProblem

__all__ = [
    "QpiAIEntropyEngine",
    "QpiAIEntropyReceipt",
    "QpiAIShorThreatReceipt",
    "ensure_qpiai_local_auth",
    "BloqCryptoAgilityOptimizer",
    "ECUAssignment",
    "ECUQAOAProblem",
]
