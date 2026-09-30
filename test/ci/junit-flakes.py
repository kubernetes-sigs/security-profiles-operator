#!/usr/bin/env python3
# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Finds e2e test cases to quarantine or to promote from the JUnit reports.

make test-flaky-e2e retries failed test cases once and records every attempt
in its JUnit report (build/junit-flaky-e2e.xml). Given the reports of several
runs, oldest first, this reports:

- test cases which are not quarantined but passed only on retry in each of the
  last --quarantine-after runs. They are flaky and fail the check.
- quarantined test cases, the ones of TestSecurityProfilesOperator_Flaky,
  which passed on the first try in each of the last --promote-after runs.
  They are candidates for promotion, see doc/hacking.md.

Each argument is the report of one run, or a directory with the reports of
one run, like the artifacts of all e2e jobs of a workflow run. The summary is
Markdown, for $GITHUB_STEP_SUMMARY. --self-test runs the tests of this
script against synthetic reports.
"""

import argparse
import pathlib
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

QUARANTINE_METHOD = "/TestSecurityProfilesOperator_Flaky/"

FIRST_TRY = "passed on the first try"
RETRY = "passed on retry"
FAILED = "failed"
SKIPPED = "skipped"


def report_files(path):
    """Returns the JUnit reports of one run."""
    path = pathlib.Path(path)
    if path.is_dir():
        return sorted(path.rglob("*.xml"))
    return [path]


def outcome(results):
    """Returns the outcome of a test case from the results of its attempts.

    Skipped attempts only count when all attempts were skipped.
    """
    ran = [result for result in results if result != SKIPPED]
    if not ran:
        return SKIPPED
    if FIRST_TRY not in ran:
        return FAILED
    if FAILED in ran:
        return RETRY
    return FIRST_TRY


def report_outcomes(report):
    """Returns the outcome of each test case of one JUnit report.

    gotestsum records each attempt of a test as its own testcase element.
    Parent tests fail with their sub tests, so the leaves count. A parent test
    only counts when it failed while none of its sub tests did, since it then
    failed on its own, like in its setup or teardown.
    """
    attempts = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        if case.find("skipped") is not None:
            result = SKIPPED
        elif case.find("failure") is not None or case.find("error") is not None:
            result = FAILED
        else:
            result = FIRST_TRY
        attempts.setdefault(case.get("name", ""), []).append(result)

    outcomes = {}
    for name, results in attempts.items():
        children = [other for other in attempts if other.startswith(name + "/")]
        if children and (
            FAILED not in results
            or any(FAILED in attempts[child] for child in children)
        ):
            continue
        outcomes[name] = outcome(results)
    return outcomes


def run_outcomes(path):
    """Returns the outcome of each test case of one run.

    A run has a report per environment. A test case skipped in one environment
    keeps the outcome of the others, a failure in any environment wins over a
    pass on retry, which wins over a pass on the first try.
    """
    per_report = [report_outcomes(report) for report in report_files(path)]
    outcomes = {}
    for name in set().union(*per_report):
        results = [report[name] for report in per_report if name in report]
        ran = [result for result in results if result != SKIPPED]
        if not ran:
            outcomes[name] = SKIPPED
        elif FAILED in ran:
            outcomes[name] = FAILED
        elif RETRY in ran:
            outcomes[name] = RETRY
        else:
            outcomes[name] = FIRST_TRY
    return outcomes


def streak(runs, name, outcome, length):
    """Reports whether the test case had the outcome in the last runs."""
    last = runs[-length:]
    return len(last) == length and all(run.get(name) == outcome for run in last)


def self_test():
    """Runs the tests of this script against synthetic reports."""
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def junit(*cases):
    """Returns a JUnit report of (name, result) test case attempts."""
    body = {
        FIRST_TRY: "",
        FAILED: "<failure message='Failed'></failure>",
        SKIPPED: "<skipped message='Skipped'></skipped>",
    }
    testcases = "".join(
        f"<testcase classname='test' name='{name}'>{body[result]}</testcase>"
        for name, result in cases
    )
    return f"<testsuites><testsuite name='test'>{testcases}</testsuite></testsuites>"


class SelfTest(unittest.TestCase):
    """Tests of the outcome calculation with synthetic reports."""

    def outcomes(self, *reports):
        """Returns the run outcomes of one report per environment."""
        with tempfile.TemporaryDirectory() as tmp:
            for i, report in enumerate(reports):
                pathlib.Path(tmp, f"env-{i}.xml").write_text(report)
            return run_outcomes(tmp)

    def test_attempts(self):
        self.assertEqual(
            self.outcomes(
                junit(
                    ("T/pass", FIRST_TRY),
                    ("T/retry", FAILED),
                    ("T/retry", FIRST_TRY),
                    ("T/fail", FAILED),
                    ("T/fail", FAILED),
                    ("T/skip", SKIPPED),
                    ("T", FAILED),
                    ("T", FAILED),
                )
            ),
            {
                "T/pass": FIRST_TRY,
                "T/retry": RETRY,
                "T/fail": FAILED,
                "T/skip": SKIPPED,
            },
        )

    def test_skip_in_one_environment(self):
        passed = junit(("T", FIRST_TRY), ("T/a", FIRST_TRY), ("T/b", FIRST_TRY))
        retried = junit(("T", FAILED), ("T/a", FAILED), ("T", FIRST_TRY), ("T/a", FIRST_TRY))
        skipped = junit(("T", FIRST_TRY), ("T/a", SKIPPED), ("T/b", SKIPPED))
        self.assertEqual(
            self.outcomes(skipped, passed),
            {"T/a": FIRST_TRY, "T/b": FIRST_TRY},
        )
        self.assertEqual(
            self.outcomes(passed, skipped, retried),
            {"T/a": RETRY, "T/b": FIRST_TRY},
        )
        self.assertEqual(
            self.outcomes(skipped, skipped),
            {"T/a": SKIPPED, "T/b": SKIPPED},
        )

    def test_failure_wins_over_retry(self):
        retried = junit(("T/a", FAILED), ("T/a", FIRST_TRY))
        failed = junit(("T/a", FAILED), ("T/a", FAILED))
        self.assertEqual(self.outcomes(retried, failed), {"T/a": FAILED})

    def test_parent_failure(self):
        # The parent failed on its own on the first try, its sub test passed.
        self.assertEqual(
            self.outcomes(
                junit(("T", FAILED), ("T/a", FIRST_TRY), ("T", FIRST_TRY), ("T/a", FIRST_TRY))
            ),
            {"T": RETRY, "T/a": FIRST_TRY},
        )
        self.assertEqual(
            self.outcomes(junit(("T", FAILED), ("T/a", FIRST_TRY), ("T", FAILED))),
            {"T": FAILED, "T/a": FIRST_TRY},
        )

    def test_streak(self):
        runs = [{"a": RETRY}, {"a": RETRY}, {"a": RETRY}]
        self.assertTrue(streak(runs, "a", RETRY, 3))
        self.assertFalse(streak(runs, "a", RETRY, 4))
        self.assertFalse(streak(runs + [{"a": FIRST_TRY}], "a", RETRY, 3))


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", nargs="+", help="JUnit report or directory per run, oldest first")
    parser.add_argument("--quarantine-after", type=int, default=3, metavar="N")
    parser.add_argument("--promote-after", type=int, default=5, metavar="N")
    parser.add_argument("--self-test", action="store_true", help="run the tests of this script and exit")
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    runs = [run_outcomes(run) for run in args.runs]
    names = sorted(set().union(*runs))

    to_quarantine = [
        name
        for name in names
        if QUARANTINE_METHOD not in name and streak(runs, name, RETRY, args.quarantine_after)
    ]
    to_promote = [
        name
        for name in names
        if QUARANTINE_METHOD in name and streak(runs, name, FIRST_TRY, args.promote_after)
    ]

    print(f"## E2E flakes of the last {len(runs)} runs\n")
    print(f"Passed only on retry in the last {args.quarantine_after} runs, quarantine them:\n")
    for name in to_quarantine or ["none"]:
        print(f"- `{name}`")
    print(f"\nQuarantined, passed on the first try in the last {args.promote_after} runs, promote them:\n")
    for name in to_promote or ["none"]:
        print(f"- `{name}`")

    return 1 if to_quarantine else 0


if __name__ == "__main__":
    sys.exit(main())
