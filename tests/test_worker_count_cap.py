"""Unit tests for run.py's check_worker_count_cap -- the soft default cap on
--exploit-worker-count/--verify-worker-count, added after a live stress test
found the real ceiling is host OS process/handle exhaustion (broke at 150
concurrent workers, clean through 80), not a MongoDB or code limit.

Run with: pytest tests/test_worker_count_cap.py -v
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from ronin_mini.run import DEFAULT_MAX_WORKER_COUNT, check_worker_count_cap  # noqa: E402


def test_default_worker_counts_pass():
    assert check_worker_count_cap(1, 1, allow_high=False) is None


def test_at_cap_passes():
    assert check_worker_count_cap(DEFAULT_MAX_WORKER_COUNT, DEFAULT_MAX_WORKER_COUNT, allow_high=False) is None


def test_exploit_over_cap_fails():
    error = check_worker_count_cap(DEFAULT_MAX_WORKER_COUNT + 1, 1, allow_high=False)
    assert error is not None
    assert "--exploit-worker-count" in error


def test_verify_over_cap_fails():
    error = check_worker_count_cap(1, DEFAULT_MAX_WORKER_COUNT + 1, allow_high=False)
    assert error is not None
    assert "--verify-worker-count" in error


def test_both_over_cap_reports_both():
    error = check_worker_count_cap(DEFAULT_MAX_WORKER_COUNT + 1, DEFAULT_MAX_WORKER_COUNT + 5, allow_high=False)
    assert "--exploit-worker-count" in error
    assert "--verify-worker-count" in error


def test_allow_high_bypasses_cap():
    assert check_worker_count_cap(500, 500, allow_high=True) is None
