import unittest

import geraveripass


class TestGeraVeriPass(unittest.TestCase):
	def test_generate_password_length(self):
		pwd = geraveripass.generate_password(length=18)
		self.assertEqual(len(pwd), 18)

	def test_generate_has_selected_groups(self):
		pwd = geraveripass.generate_password(length=12, upper=True, lower=True, digits=True, symbols=True)
		self.assertRegex(pwd, r"[A-Z]")
		self.assertRegex(pwd, r"[a-z]")
		self.assertRegex(pwd, r"\d")
		self.assertRegex(pwd, r"[^A-Za-z0-9]")

	def test_strength_labels(self):
		weak = geraveripass.evaluate_strength("1234")
		strong = geraveripass.evaluate_strength("V$9mQa2#xT7!kW")
		self.assertEqual(weak["label"], "Fraca")
		self.assertIn(strong["label"], ["Média", "Forte"])

	def test_crack_time_format(self):
		result = geraveripass.estimate_crack_time("Abc123!@#")
		self.assertIn("readable", result)
		self.assertTrue(len(result["readable"]) > 0)


if __name__ == "__main__":
	unittest.main()

