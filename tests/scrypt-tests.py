import unittest

import scrypt

class TestScrypt(unittest.TestCase):
    def test_encrypt(self):
        s = scrypt.encrypt('message', 'password', .1)
        self.assertEqual(len(s), 128+len('message'))
        
    def test_encrypt_decrypt(self):
        orig_m = 'message'
        s = scrypt.encrypt(orig_m, 'password', .1)
        m = scrypt.decrypt(s, 'password', .1)
        self.assertEqual(m, orig_m)
        
    def test_too_little_time(self):
        orig_m = 'message'
        s = scrypt.encrypt(orig_m, 'password', .1)
        self.assertRaises(scrypt.error, lambda: scrypt.decrypt(s, 'password', .01))
        
if __name__ == '__main__':
    unittest.main()
