"""
test_evaluation.py - Ground-Truth Evaluation Suite for QuantumShield Risk Engine

Loads synthetic ground-truth test cases from fixtures, runs the Risk Engine,
verifies every field, and computes evaluation metrics against the synthetic dataset.
"""

import os
import sys
import json
import unittest
from typing import Dict, Any, List

# Ensure repository root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.risk_engine import analyze_findings


FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "synthetic_eval_cases.json")


def run_benchmark_evaluation() -> Dict[str, Any]:
    """
    Executes the risk engine against the synthetic ground-truth dataset
    and calculates match metrics per field and per case.
    """
    if not os.path.exists(FIXTURES_PATH):
        raise FileNotFoundError(f"Fixture file not found: {FIXTURES_PATH}")

    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        cases = json.load(f)

    findings = [
        {
            "case_id": c["id"],
            "file_path": c["file_path"],
            "line_number": c["line_number"],
            "language": c["language"],
            "algorithm": c["algorithm"],
            "matched_pattern": c["matched_pattern"],
            "evidence": c["evidence"],
        }
        for c in cases
    ]

    actual_results = analyze_findings(findings)

    total_cases = len(cases)
    field_matches = {
        "risk_level": 0,
        "cryptographic_purpose": 0,
        "migration_priority": 0,
        "manual_review_required": 0,
    }
    mismatches: List[Dict[str, Any]] = []

    for expected_case, actual in zip(cases, actual_results):
        exp = expected_case["expected"]
        case_id = expected_case["id"]
        case_mismatches = {}

        for field in field_matches.keys():
            if actual.get(field) == exp.get(field):
                field_matches[field] += 1
            else:
                case_mismatches[field] = {
                    "expected": exp.get(field),
                    "actual": actual.get(field),
                }

        if case_mismatches:
            mismatches.append({
                "case_id": case_id,
                "algorithm": expected_case["algorithm"],
                "mismatches": case_mismatches,
                "rationale": expected_case.get("rationale", ""),
            })

    total_checks = total_cases * len(field_matches)
    total_passed_checks = sum(field_matches.values())
    field_accuracies = {
        k: (v / total_cases) * 100.0 for k, v in field_matches.items()
    }
    overall_accuracy = (total_passed_checks / total_checks) * 100.0

    return {
        "total_cases": total_cases,
        "field_matches": field_matches,
        "field_accuracies": field_accuracies,
        "overall_accuracy": overall_accuracy,
        "mismatches": mismatches,
    }


class TestSyntheticEvaluation(unittest.TestCase):
    """Verifies that actual risk engine output conforms 100% to synthetic ground-truth specifications."""

    def test_fixtures_file_exists_and_valid(self):
        """Fixture JSON must be readable and contain non-empty list of cases."""
        self.assertTrue(os.path.exists(FIXTURES_PATH), f"Fixture missing: {FIXTURES_PATH}")
        with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
            cases = json.load(f)
        self.assertIsInstance(cases, list)
        self.assertGreater(len(cases), 0)

    def test_all_synthetic_cases_match_expected(self):
        """Every case in the synthetic benchmark must match expected ground-truth labels."""
        results = run_benchmark_evaluation()
        mismatches = results["mismatches"]
        if mismatches:
            mismatch_report = json.dumps(mismatches, indent=2)
            self.fail(f"Found {len(mismatches)} mismatches in synthetic evaluation:\n{mismatch_report}")

        self.assertEqual(results["overall_accuracy"], 100.0)
        self.assertEqual(len(mismatches), 0)


if __name__ == "__main__":
    report = run_benchmark_evaluation()
    print("=" * 60)
    print("QUANTUMSHIELD - RISK ENGINE SYNTHETIC EVALUATION REPORT")
    print("=" * 60)
    print(f"Total Cases Evaluated: {report['total_cases']}")
    print("-" * 60)
    print("Per-Field Accuracy:")
    for field, acc in report["field_accuracies"].items():
        print(f"  - {field:25s}: {acc:6.2f}% ({report['field_matches'][field]}/{report['total_cases']})")
    print("-" * 60)
    print(f"Overall Ground-Truth Concordance: {report['overall_accuracy']:.2f}%")
    if report["mismatches"]:
        print(f"Mismatches ({len(report['mismatches'])}):")
        for m in report["mismatches"]:
            print(f"  Case {m['case_id']} ({m['algorithm']}): {m['mismatches']}")
    else:
        print("Status: All synthetic evaluation test cases matched expected labels.")
    print("=" * 60)
