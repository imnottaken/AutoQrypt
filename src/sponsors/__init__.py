"""
Q-Shield AutoQrypt - Sponsor Integrations
Tier 1: QpiAI QCloud (Quantum Entropy & QRNG Seeding)
Tier 2: Bloq Platform (Quantum Crypto-Agility & Hardware Constrained Optimization)
"""

from .qpiai_qcloud import QpiAIEntropyEngine, QpiAIEntropyReceipt
from .bloq_platform import BloqCryptoAgilityOptimizer, ECUAssignment

__all__ = [
    "QpiAIEntropyEngine",
    "QpiAIEntropyReceipt",
    "BloqCryptoAgilityOptimizer",
    "ECUAssignment"
]
