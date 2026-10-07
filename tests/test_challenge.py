import hashlib
import unittest

from bot_guard import BehaviorTracker, ChallengeManager


class ChallengeTests(unittest.TestCase):
    def test_pow_and_attestation(self):
        manager = ChallengeManager("0123456789abcdef", difficulty=1, challenge_ttl=60)
        token = manager.issue("client")
        solution = next(str(i) for i in range(100) if hashlib.sha256((token + str(i)).encode()).hexdigest().startswith("0"))
        self.assertTrue(manager.verify(token, solution, "client"))
        self.assertFalse(manager.verify(token, solution, "client"))
        self.assertFalse(manager.verify(token, solution, "other"))
        self.assertFalse(manager.verify(token, "wrong", "client"))
        attestation = manager.issue_attestation("client")
        self.assertTrue(manager.verify_attestation(attestation, "client"))
        self.assertFalse(manager.verify_attestation(attestation, "other"))

    def test_tampering_and_rendering(self):
        manager = ChallengeManager("0123456789abcdef", difficulty=1)
        token = manager.issue("client")
        tampered = token[:-1] + ("a" if token[-1] != "a" else "b")
        self.assertFalse(manager.verify(tampered, "0", "client"))
        page = manager.render(token, next_url="/")
        self.assertIn("crypto.subtle", page)
        self.assertNotIn("0123456789abcdef", page)

    def test_browser_probe_pow_is_client_bound_one_time_and_attestation_signed(self):
        manager = ChallengeManager("0123456789abcdef", difficulty=1, challenge_ttl=60, attestation_ttl=60)
        token = manager.issue_browser_probe("peer-ip")
        difficulty = manager.browser_probe_difficulty(token, "peer-ip")
        self.assertEqual(difficulty, 1)
        solution = next(str(i) for i in range(100)
                        if hashlib.sha256((token + str(i)).encode()).hexdigest().startswith("0"))
        invalid_solution = next(str(i) for i in range(100)
                                if not hashlib.sha256((token + str(i)).encode()).hexdigest().startswith("0"))
        self.assertFalse(manager.verify_browser_probe(token, solution, "other-ip"))
        self.assertFalse(manager.verify_browser_probe(token, invalid_solution, "peer-ip"))
        self.assertTrue(manager.verify_browser_probe(token, solution, "peer-ip"))
        self.assertFalse(manager.verify_browser_probe(token, solution, "peer-ip"))

        attestation = manager.issue_browser_attestation("peer-ip", automation_detected=True, interaction_count=2)
        payload = manager.read_browser_attestation(attestation, "peer-ip")
        self.assertTrue(manager.verify_browser_attestation(attestation, "peer-ip"))
        self.assertEqual(payload["interactions"], 2)
        self.assertFalse(manager.verify_browser_attestation(attestation, "other-ip"))

    def test_render_escapes_script_context_values(self):
        manager = ChallengeManager("0123456789abcdef", difficulty=1)
        page = manager.render("safe-token", verify_url='</script><script>alert(1)</script>', next_url='x\\"</script>')
        self.assertEqual(page.count("</script>"), 1)  # only the page's closing tag
        self.assertIn("\\u003c/script\\u003e", page)

    def test_behavior_history(self):
        tracker = BehaviorTracker(window=60, burst_threshold=3, path_threshold=3)
        for path in ("/a", "/b", "/c"):
            tracker.observe("client", path, 200)
        self.assertGreater(tracker.score({}, "client", {}), 0.0)
        self.assertEqual(tracker.score({}, "other", {}), 0.0)


if __name__ == "__main__":
    unittest.main()
