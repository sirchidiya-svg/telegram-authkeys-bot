"""
Smoke test for the export-partition fix.

Before this fix, find_all_records(user_id) ignored chat_id entirely, so running
/export_my_data inside a group would leak a user's DM-saved entries into that group.
This test saves one entry in a DM-like chat and one in a group-like chat for the
same user, then verifies each chat's export only ever sees its own entry.
"""
import os
import tempfile
import unittest


class ExportPartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Isolated DB + env so this never touches a real deployment's data.
        cls._tmpdir = tempfile.mkdtemp()
        os.environ["TELEGRAM_TOKEN"] = "dummy"
        from cryptography.fernet import Fernet
        os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

        import app as app_module
        cls.app = app_module
        cls.app.DB_PATH = os.path.join(cls._tmpdir, "test_authkeys.db")
        cls.app.init_db()

    def test_dm_entry_never_appears_in_group_export(self):
        app = self.app
        user_id = 111
        dm_chat_id = 111          # Telegram DMs: chat_id == user_id
        group_chat_id = -999      # Telegram groups: negative chat_id

        app.save_record(user_id, dm_chat_id, "Alice", "dm-secret", "only in DM", "11112222")
        app.save_record(user_id, group_chat_id, "Alice", "group-secret", "only in group", "33334444")

        dm_export = app.find_all_records(user_id, dm_chat_id)
        group_export = app.find_all_records(user_id, group_chat_id)

        dm_titles = {row[0] for row in dm_export}
        group_titles = {row[0] for row in group_export}

        self.assertIn("dm-secret", dm_titles)
        self.assertNotIn("group-secret", dm_titles)   # the leak this fix closes

        self.assertIn("group-secret", group_titles)
        self.assertNotIn("dm-secret", group_titles)   # partition holds both directions

    def test_team_export_only_includes_this_group(self):
        app = self.app
        group_a = -111
        group_b = -222

        app.save_record(201, group_a, "Bob", "shared-a", "belongs to group A", "AAAA1111")
        app.save_record(202, group_b, "Carol", "shared-b", "belongs to group B", "BBBB2222")

        team_a = app.find_all_team_records(group_a)
        team_b = app.find_all_team_records(group_b)

        self.assertEqual({row[0] for row in team_a}, {"shared-a"})
        self.assertEqual({row[0] for row in team_b}, {"shared-b"})

    def test_only_key_generating_commands_carry_credit_limit(self):
        import inspect
        app = self.app

        def spends_credit(func):
            src = inspect.getsource(func)
            return "check_credit_allowed" in src or getattr(func, "__wrapped__", None)

        # generate_numeric / generate_alphanumeric are wrapped by credit_limit,
        # so their __wrapped__ attr will exist (functools.wraps sets it).
        self.assertTrue(hasattr(app.generate_numeric, "__wrapped__"))
        self.assertTrue(hasattr(app.generate_alphanumeric, "__wrapped__"))

        # These must NOT be credit-limited anymore.
        for fn in (app.save_command, app.find_command, app.delete_command,
                   app.delete_all_my_data_command, app.export_my_data_command):
            src = inspect.getsource(fn)
            self.assertNotIn("check_credit_allowed", src)


if __name__ == "__main__":
    unittest.main()
