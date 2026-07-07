import unittest

from app import build_find_response


class FindResponseTests(unittest.TestCase):
    def test_generated_key_is_rendered_as_copyable_code(self):
        response = build_find_response(
            title="api1",
            details="my-api-key",
            generated_key="ABC12345",
            created_at="2026-07-07 12:00:00 UTC",
        )

        self.assertIn("Generated key: `ABC12345`", response)
        self.assertNotIn("Generated key: ABC12345", response)


if __name__ == "__main__":
    unittest.main()
