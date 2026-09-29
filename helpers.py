"""Shared test helpers."""

# Cheap scrypt settings so the test-suite runs fast (production uses n=2**15).
FAST_KDF = {"n": 2**10, "r": 8, "p": 1}
MASTER = "Correct-Horse9"
