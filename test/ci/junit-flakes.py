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

- test cases which are not quarantined but passed only on retry in at least
  --quarantine-after of the last --quarantine-window runs. They are flaky and
  fail the check. Failures do not count: a broken test case, or a run which
  failed partway, fails the e2e jobs on its own.
- TestSuite and its methods, which passed only on retry like that. They
  failed on their own, like in the setup of the cluster, which no quarantine
  helps against, so they do not fail the check.
- quarantined test cases, the ones of TestSecurityProfilesOperator_Flaky,
  which ran in the newest run and passed on the first try in each of the last
  --promote-after runs in which they ran. Runs which skipped them or have no
  report of them do not count, like ones whose job failed without report or
  skipped the suite on a slow runner. The complete reports of a job which ran
  a test case before, but which leave it out, count as a failure, like the
  ones of a test binary which timed out or crashed, unless the test case
  moved to another job. They are candidates for promotion, see
  doc/hacking.md.

Each argument is the report of one run, or a directory with the reports of
one run, like the artifacts of all e2e jobs of a workflow run, one directory
per job, whose name tells the job. The jobs of a sharded suite end with
-shard-N-of-M, and the reports of such a job are complete when the run has
all M of them. Before the total was part of the name, they ended with
-shard-N, which leaves their completeness unknown: the outcomes in them
count, a test case missing from them does not. The summary is
Markdown, for $GITHUB_STEP_SUMMARY. --self-test runs the tests of this
script against synthetic reports.
"""

import argparse
import pathlib
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

QUARANTINE_METHOD = "/TestSecurityProfilesOperator_Flaky/"

FIRST_TRY = "passed on the first try"
RETRY = "passed on retry"
FAILED = "failed"
SKIPPED = "skipped"

# The suffix of the jobs of a sharded suite, like e2e-kind-shard-2-of-3.
SHARD_SUFFIX = re.compile(r"-shard-\d+-of-(?P<total>\d+)$")
# The suffix of the jobs of a sharded suite before the total was part of it.
LEGACY_SHARD_SUFFIX = re.compile(r"-shard-\d+$")

# The suite method which runs the quarantined test cases.
QUARANTINE_SUITE_METHOD = "TestSuite" + QUARANTINE_METHOD.rstrip("/")


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


def report_job(report):
    """Returns the job of a report, the directory it got downloaded to without
    the shard suffix, and the number of its shards, None if unknown."""
    name = pathlib.Path(report).parent.name
    if match := SHARD_SUFFIX.search(name):
        return name[: match.start()], int(match.group("total"))
    if match := LEGACY_SHARD_SUFFIX.search(name):
        return name[: match.start()], None
    return name, 1


def reached_quarantine(outcomes):
    """Reports whether the test binary of a report got to the quarantined test
    cases: it has one of them, or skipped them all, like a shard without
    any."""
    return outcomes.get(QUARANTINE_SUITE_METHOD) == SKIPPED or any(
        QUARANTINE_METHOD in name for name in outcomes
    )


def run_jobs(path):
    """Returns the jobs of one run, each with whether its reports are
    complete, see missing_failed, and the outcomes of its test cases."""
    reports = {}
    for report in report_files(path):
        job, total = report_job(report)
        reports.setdefault(job, (total, []))[1].append(report_outcomes(report))

    jobs = {}
    for job, (total, per_report) in reports.items():
        outcomes = {
            name: combine([o[name] for o in per_report if name in o])
            for name in set().union(*per_report)
        }
        complete = (
            total is not None
            and len(per_report) == total
            and all(reached_quarantine(o) for o in per_report)
        )
        jobs[job] = (complete, outcomes)
    return jobs


def combine(results):
    """Returns the outcome of a test case from its outcomes in several reports.

    A test case skipped in one report keeps the outcome of the others, a
    failure in any report wins over a pass on retry, which wins over a pass on
    the first try.
    """
    ran = [result for result in results if result != SKIPPED]
    if not ran:
        return SKIPPED
    if FAILED in ran:
        return FAILED
    if RETRY in ran:
        return RETRY
    return FIRST_TRY


def missing_failed(runs_jobs):
    """Returns the outcomes of each run, given the jobs of the runs, oldest
    first.

    A test case which a job ran in an earlier run, but which the complete
    reports of that job leave out, failed in that run: the test binary timed
    out or crashed before it got to the test case. A run without complete
    reports of the job does not change that. A test case which runs in a new
    job moved there from the jobs whose complete reports of that run leave it
    out, which do not count anymore, without a failure, neither does a job
    whose complete reports skip it. The reports of a job are complete
    when the run has a report of each of its shards, and the test binary of
    each one got to the quarantined test cases, so that a shard which failed
    in its setup does not count against them.
    """
    # The jobs which run each test case, as far as the earlier runs tell.
    ran_by = {}
    runs = []
    for jobs in runs_jobs:
        ran_now = {}
        for job, (_, job_outcomes) in jobs.items():
            for name, result in job_outcomes.items():
                if result != SKIPPED:
                    ran_now.setdefault(name, set()).add(job)

        outcomes = {}
        for name in set().union(*(o for _, o in jobs.values())):
            outcomes[name] = combine([o[name] for _, o in jobs.values() if name in o])

        for name in set(ran_by) | set(ran_now):
            before, now = ran_by.get(name, set()), ran_now.get(name, set())
            moved = bool(now - before)
            kept = set()
            for job in before:
                complete, job_outcomes = jobs.get(job, (False, {}))
                if not complete:
                    # A run without complete reports of the job does not
                    # tell whether it still runs the test case.
                    kept.add(job)
                elif name not in job_outcomes:
                    # The test case runs in a new job now, so it moved there
                    # from the jobs which leave it out. Otherwise the test
                    # binary of the job timed out or crashed before it.
                    if not moved:
                        kept.add(job)
                        if is_test_case(name):
                            outcomes[name] = FAILED
                elif job_outcomes[name] != SKIPPED:
                    kept.add(job)
            ran_by[name] = now | kept
        runs.append(outcomes)
    return runs


def streak(runs, name, outcome, length):
    """Reports whether the test case had the outcome in the last runs in which
    it ran.

    Runs which skipped the test case, or have no report of it, do not count.
    The test cases of a single environment, like the SELinux ones, would
    otherwise rarely get a streak, since every run in which their job failed or
    got skipped breaks it. A complete report which leaves out a test case its
    job runs counts as a failure, see missing_failed.
    """
    ran = [run[name] for run in runs if run.get(name, SKIPPED) != SKIPPED]
    last = ran[-length:]
    return len(last) == length and all(result == outcome for result in last)


def promotable(runs, name, length):
    """Reports whether the quarantined test case passed on the first try in
    the last runs which ran it.

    It has to have run in the newest run as well, which leaves out a test case
    whose job uploaded no report in the newest run, although the other jobs
    list it as skipped, and one which got promoted, renamed or deleted since,
    which the newest run does not have under its name anymore, or fails in it,
    see missing_failed.
    """
    return (
        QUARANTINE_METHOD in name
        and bool(runs)
        and runs[-1].get(name) not in (None, SKIPPED)
        and streak(runs, name, FIRST_TRY, length)
    )


def is_test_case(name):
    """Reports whether the name is the one of a test case.

    The test cases run below a method of TestSuite, like
    TestSuite/TestSecurityProfilesOperator/Seccomp_Basic_Profile. The others
    are TestSuite and its methods, which cannot be quarantined.
    """
    return name.count("/") >= 2


def flaky(runs, name, count, window):
    """Reports whether the test case is flaky in the last runs.

    It is when it passed only on retry in at least count of the last window
    runs. Unlike a streak, a flake which needs a retry only now and then gets
    caught too.
    """
    return [run.get(name) for run in runs[-window:]].count(RETRY) >= count


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
        """Returns the outcomes of a run with one job and report per
        environment."""
        return self.runs({f"env-{i}": report for i, report in enumerate(reports)})[0]

    def runs(self, *runs):
        """Returns the outcomes of runs, each a map of job directories to
        their reports."""
        jobs = []
        with tempfile.TemporaryDirectory() as tmp:
            for i, run in enumerate(runs):
                for job, report in run.items():
                    path = pathlib.Path(tmp, str(i), job)
                    path.mkdir(parents=True)
                    pathlib.Path(path, "junit-flaky-e2e.xml").write_text(report)
                jobs.append(run_jobs(pathlib.Path(tmp, str(i))))
        return missing_failed(jobs)

    def test_missing_from_complete_report(self):
        flaky = "TestSuite" + QUARANTINE_METHOD
        a, b = flaky + "a", flaky + "b"
        both = junit((a, FIRST_TRY), (b, FIRST_TRY))
        # The test binary timed out in a and never got to b.
        timed_out = junit((a, FAILED))
        skipped = junit((a, SKIPPED), (b, SKIPPED))
        runs = self.runs(
            {"e2e-vm": both, "e2e-kind": skipped},
            {"e2e-vm": timed_out, "e2e-kind": skipped},
            # The job uploaded no report.
            {"e2e-kind": skipped},
            # The job failed in its setup, before the quarantined test cases.
            {"e2e-vm": junit(("TestSuite", FAILED)), "e2e-kind": skipped},
        )
        self.assertEqual([run.get(b) for run in runs], [FIRST_TRY, FAILED, SKIPPED, SKIPPED])

    def test_missing_shard(self):
        flaky = "TestSuite" + QUARANTINE_METHOD
        a, b = flaky + "a", flaky + "b"
        one, two = "e2e-kind-shard-1-of-2", "e2e-kind-shard-2-of-2"
        runs = self.runs(
            {one: junit((a, FIRST_TRY)), two: junit((b, FIRST_TRY))},
            # A shard without report may be the one of the test case.
            {one: junit((a, FIRST_TRY))},
            # The test case moved to another shard.
            {one: junit((a, FIRST_TRY), (b, FIRST_TRY)), two: junit((a, SKIPPED))},
            # The shards are complete, but none has the test case.
            {one: junit((a, FIRST_TRY)), two: junit((a, SKIPPED))},
            # A single shard now, which is complete on its own.
            {"e2e-kind-shard-1-of-1": junit((a, FIRST_TRY))},
            # A shard without quarantined test cases skips them all.
            {one: junit((a, FIRST_TRY)), two: junit((QUARANTINE_SUITE_METHOD, SKIPPED))},
            # Shard names without the total leave the completeness unknown.
            {"e2e-kind-shard-1": junit((a, FIRST_TRY)), "e2e-kind-shard-2": junit((a, SKIPPED))},
        )
        self.assertEqual(
            [run.get(b) for run in runs],
            [FIRST_TRY, None, FIRST_TRY, FAILED, FAILED, FAILED, None],
        )

    def test_moved_to_other_job(self):
        flaky = "TestSuite" + QUARANTINE_METHOD
        a, b = flaky + "a", flaky + "b"
        runs = self.runs(
            {"e2e-ubuntu": junit((a, FIRST_TRY), (b, FIRST_TRY)), "e2e-kind": junit((a, FIRST_TRY))},
            # b runs in e2e-kind now, the complete report of e2e-ubuntu does
            # not fail it.
            {"e2e-ubuntu": junit((a, FIRST_TRY)), "e2e-kind": junit((a, FIRST_TRY), (b, FIRST_TRY))},
            {"e2e-ubuntu": junit((a, FIRST_TRY)), "e2e-kind": junit((a, FIRST_TRY), (b, FIRST_TRY))},
            # The test binary of e2e-kind timed out before b.
            {"e2e-ubuntu": junit((a, FIRST_TRY)), "e2e-kind": junit((a, FAILED))},
        )
        self.assertEqual([run.get(b) for run in runs], [FIRST_TRY, FIRST_TRY, FIRST_TRY, FAILED])

    def test_crash_after_run_without_report(self):
        flaky = "TestSuite" + QUARANTINE_METHOD
        a, b = flaky + "a", flaky + "b"
        both = junit((a, FIRST_TRY), (b, FIRST_TRY))
        runs = self.runs(
            {"e2e-ubuntu": both, "e2e-kind": both},
            # e2e-ubuntu uploaded no report, like when its flaky step got
            # skipped.
            {"e2e-kind": both},
            # Its test binary crashed before b, while e2e-kind passes it.
            {"e2e-ubuntu": junit((a, FAILED)), "e2e-kind": both},
            {"e2e-ubuntu": junit((a, FAILED)), "e2e-kind": both},
        )
        self.assertEqual([run.get(b) for run in runs], [FIRST_TRY, FIRST_TRY, FAILED, FAILED])

    def test_crash_after_move_run_without_report(self):
        flaky = "TestSuite" + QUARANTINE_METHOD
        a, b = flaky + "a", flaky + "b"
        both = junit((a, FIRST_TRY), (b, FIRST_TRY))
        runs = self.runs(
            {"e2e-ubuntu": both, "e2e-kind": junit((a, FIRST_TRY))},
            # e2e-kind runs b as well now, while e2e-ubuntu uploaded no
            # report, so it may still run b.
            {"e2e-kind": both},
            # Its test binary crashed before b.
            {"e2e-ubuntu": junit((a, FAILED)), "e2e-kind": both},
        )
        self.assertEqual([run.get(b) for run in runs], [FIRST_TRY, FIRST_TRY, FAILED])

    def test_shard_setup_failure(self):
        flaky = "TestSuite" + QUARANTINE_METHOD
        a, b = flaky + "a", flaky + "b"
        one, two = "e2e-kind-shard-1-of-2", "e2e-kind-shard-2-of-2"
        passed = {
            one: junit(("TestSuite", FIRST_TRY), (QUARANTINE_SUITE_METHOD, FIRST_TRY), (a, FIRST_TRY)),
            two: junit(("TestSuite", FIRST_TRY), (QUARANTINE_SUITE_METHOD, FIRST_TRY), (b, FIRST_TRY)),
        }
        # The second shard failed in its setup, before its test cases.
        setup_failure = dict(passed)
        setup_failure[two] = junit(("TestSuite", FAILED), (QUARANTINE_SUITE_METHOD, FAILED))
        runs = self.runs(passed, setup_failure, passed)
        self.assertEqual([run.get(b) for run in runs], [FIRST_TRY, None, FIRST_TRY])

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
        # Runs which skipped the test case or have no report of it do not
        # count, neither for nor against the streak.
        passed = {"a": FIRST_TRY}
        skipped = [{"a": SKIPPED}, {}]
        self.assertTrue(streak([passed, *skipped, passed, *skipped], "a", FIRST_TRY, 2))
        self.assertFalse(streak([passed, *skipped], "a", FIRST_TRY, 2))
        self.assertFalse(streak(skipped * 3, "a", FIRST_TRY, 1))
        # The reports do not tell why a test case is missing, so a run whose
        # job died before uploading its report does not break the streak.
        self.assertTrue(streak([passed, {"b": FAILED}, passed], "a", FIRST_TRY, 2))
        # A failure in a run before the streak does not count.
        self.assertTrue(streak([{"a": FAILED}, passed, {}, passed], "a", FIRST_TRY, 2))
        self.assertFalse(streak([passed, {"a": FAILED}, {}, passed], "a", FIRST_TRY, 2))

    def test_promotable(self):
        name = "TestSuite" + QUARANTINE_METHOD + "a"
        passed = {name: FIRST_TRY}
        self.assertTrue(promotable([passed, passed], name, 2))
        # Promoted since, the newest run has it under another method.
        self.assertFalse(promotable([passed, passed, {"TestSuite/T/a": FIRST_TRY}], name, 2))
        self.assertFalse(promotable([{"TestSuite/T/a": FIRST_TRY}] * 2, "TestSuite/T/a", 2))
        # Its job uploaded no report in the newest run, the others skip it.
        self.assertFalse(promotable([passed, passed, {name: SKIPPED}], name, 2))

    def test_flaky(self):
        passed, retried, failed = {"a": FIRST_TRY}, {"a": RETRY}, {"a": FAILED}
        runs = [retried] + [passed] * 4 + [retried] + [passed] * 4
        self.assertTrue(flaky(runs, "a", 2, 10))
        # The first retry dropped out of the window.
        self.assertFalse(flaky(runs + [passed], "a", 2, 10))
        self.assertFalse(flaky([retried] + [passed] * 9, "a", 2, 10))
        # Failures do not count, like the ones of a run which failed partway.
        self.assertFalse(flaky([failed] * 10, "a", 2, 10))
        self.assertFalse(flaky([retried] + [failed] * 9, "a", 2, 10))
        self.assertTrue(flaky([passed] * 8 + [retried, retried], "a", 2, 10))
        # Runs without the test case, like skipped ones, do not count.
        self.assertFalse(flaky([retried, {}, {"a": SKIPPED}], "a", 2, 10))

    def test_is_test_case(self):
        self.assertTrue(is_test_case("TestSuite/TestSecurityProfilesOperator/a"))
        self.assertTrue(is_test_case("TestSuite/TestSecurityProfilesOperator_Flaky/a"))
        self.assertFalse(is_test_case("TestSuite/TestSecurityProfilesOperator_Flaky"))
        self.assertFalse(is_test_case("TestSuite"))


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", nargs="+", help="JUnit report or directory per run, oldest first")
    parser.add_argument("--quarantine-after", type=int, default=2, metavar="N")
    parser.add_argument("--quarantine-window", type=int, default=10, metavar="M")
    parser.add_argument("--promote-after", type=int, default=10, metavar="N")
    parser.add_argument("--self-test", action="store_true", help="run the tests of this script and exit")
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    runs = missing_failed([run_jobs(run) for run in args.runs])
    names = sorted(set().union(*runs))

    flakes = [
        name for name in names if flaky(runs, name, args.quarantine_after, args.quarantine_window)
    ]
    to_quarantine = [
        name for name in flakes if is_test_case(name) and QUARANTINE_METHOD not in name
    ]
    setup_flakes = [name for name in flakes if not is_test_case(name)]
    to_promote = [name for name in names if promotable(runs, name, args.promote_after)]

    print(f"## E2E flakes of the last {len(runs)} runs\n")
    print(
        f"Passed only on retry in at least {args.quarantine_after} of the last "
        f"{args.quarantine_window} runs, quarantine them:\n"
    )
    for name in to_quarantine or ["none"]:
        print(f"- `{name}`")
    print("\nThe suite or its methods passed only on retry like that, check their setup:\n")
    for name in setup_flakes or ["none"]:
        print(f"- `{name}`")
    print(
        f"\nQuarantined, passed on the first try in the last {args.promote_after} runs "
        "which ran them, promote them:\n"
    )
    for name in to_promote or ["none"]:
        print(f"- `{name}`")

    return 1 if to_quarantine else 0


if __name__ == "__main__":
    sys.exit(main())
