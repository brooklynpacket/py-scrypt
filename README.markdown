Python [scrypt][] bindings
==========================

This is a set of [Python][] bindings for the [scrypt][] key derivation function.

Scrypt is useful when encrypting password as it is possible to specify a
**minimum** amount of time to use when encrypting and decrypting. If, for
example, a password takes 0.05 seconds to verify, a user won't notice the
slight delay when signing in, but doing a brute force search of several
billion passwords will take a considerable amount of time. This is in
contrast to more traditional hash functions such as MD5 or the SHA family
which can be implemented extremely fast on cheap hardware.

Installation
------------

    $ hg clone http://bitbucket.org/mhallin/py-scrypt
    $ cd py-scrypt
    $ python setup.py build

    Become superuser (or use virtualenv):
    # python setup.py install

    Run tests after install:
    $ python tests/scrypt-tests.py


If you want py-scrypt for your Python 3 environment, just run the
above commands with your Python 3 interpreter. Py-scrypt supports both
Python 2 and 3.

Usage
-----

The bindings are very simple -- there is an encrypt and a decrypt method on
the scrypt module:

	>>> import scrypt
	>>> data = scrypt.encrypt('a secret message', 'password', maxtime=0.1) # This will take at least 0.1 seconds
	>>> data[:20]
	'scrypt\x00\r\x00\x00\x00\x08\x00\x00\x00\x01RX9H'
	>>> scrypt.decrypt(data, 'password', maxtime=0.1) # This will also take at least 0.1 seconds
	'a secret message'
	>>> scrypt.decrypt(data, 'password', maxtime=0.05) # scrypt won't be able to decrypt this data fast enough
	Traceback (most recent call last):
	  File "<stdin>", line 1, in <module>
	scrypt.error: decrypting file would take too long
	>>> scrypt.decrypt(data, 'wrong password', maxtime=0.1) # scrypt will throw an exception if the password is incorrect
	Traceback (most recent call last):
	  File "<stdin>", line 1, in <module>
	scrypt.error: password is incorrect

From these, one can make a simple password verifier using the following
functions:

	def randstr(length):
	    return ''.join(chr(random.randint(0,255)) for i in range(length))

	def hash_password(password, maxtime=0.5, datalength=64):
	    return scrypt.encrypt(randstr(datalength), password, maxtime=maxtime)

	def verify_password(hashed_password, guessed_password, maxtime=0.5):
		try:
			scrypt.decrypt(hashed_password, guessed_password, maxtime)
			return True
		except scrypt.error:
			return False

Acknowledgements
----------------

[Scrypt][] was created by Colin Percival and is licensed as 2-clause BSD.
Since scrypt does not normally build as a shared library, I have included
the source for the currently latest version of the library in this
repository. When a new version arrives, I will update these sources.

[Burstaholic][] on Bitbucket provided the necessary changes to make
the library build on Windows.

[Kelvin Wong][] on Bitbucket provided changes to make the library available
on Mac OS X 10.6 and earlier, as well as changes to make the library
work more like the command-line version of scrypt by default.

License
-------

This library is licensed under the same license as scrypt; 2-clause BSD.

[scrypt]: http://www.tarsnap.com/scrypt.html
[Python]: http://python.org
[Burstaholic]: https://bitbucket.org/Burstaholic
