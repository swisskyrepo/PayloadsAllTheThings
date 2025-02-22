import unittest
import re

class TestPythonMd(unittest.TestCase):
    def test_python_code_blocks(self):
        with open('Insecure Deserialization/Python.md', 'r') as file:
            content = file.read()

        # Extract Python code blocks
        code_blocks = re.findall(r'```python(.*?)```', content, re.DOTALL)

        for code in code_blocks:
            try:
                exec(code)
            except Exception as e:
                self.fail(f"Code block failed to execute: {e}")

if __name__ == '__main__':
    unittest.main()
