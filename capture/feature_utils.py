# ============================================
# Shared Feature Utilities
# ============================================
# Helper functions used by both capture pipeline and preprocessing.
# Example: Shannon entropy calculation, window aggregation logic.
# ============================================

import math
from collections import Counter


def shannon_entropy(values):
    """Compute Shannon entropy of a list of values (e.g., destination ports)."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy
