/*-
 * Copyright 2010 Magnus Hallin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <Python.h>

#include "scryptenc/scryptenc.h"
#include "crypto/crypto_scrypt.h"

static PyObject *ScryptError;

static const char *g_error_codes[] = {
    "success",
    "getrlimit or sysctl(hw.usermem) failed",
    "clock_getres or clock_gettime failed",
    "error computing derived key",
    "could not read salt from /dev/urandom",
    "error in OpenSSL",
    "malloc failed",
    "data is not a valid scrypt-encrypted block",
    "unrecognized scrypt format",
    "decrypting file would take too much memory",
    "decrypting file would take too long",
    "password is incorrect",
    "error writing output file",
    "error reading input file"
};
static char *g_kwlist[] = {"input", "password", "maxtime", "maxmem", "maxmemfrac", NULL};
static const size_t g_maxmem_default = 0;
static const double g_maxmemfrac_default = 0.5;
static const double g_maxmemfrac_default_enc = 0.125;
static const double g_maxtime_default = 300.0;
static const double g_maxtime_default_enc = 5.0;

static PyObject *scrypt_encrypt(PyObject *self, PyObject *args, PyObject *kwargs) {
    PyStringObject *input, *password;
    int inputlen, passwordlen;
    int errorcode;
    size_t maxmem = g_maxmem_default;
    double maxmemfrac = g_maxmemfrac_default_enc;
    double maxtime = g_maxtime_default_enc;
    uint8_t *outbuf;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "SS|dnd", g_kwlist,
                                     &input, &password,
                                     &maxtime, &maxmem, &maxmemfrac)) {
        return NULL;
    }

    Py_INCREF(input);
    Py_INCREF(password);

    inputlen = PyString_Size((PyObject*) input);
    passwordlen = PyString_Size((PyObject*) password);

    outbuf = PyMem_Malloc(inputlen+129);

    Py_BEGIN_ALLOW_THREADS;
    errorcode = scryptenc_buf((uint8_t *) PyString_AsString((PyObject*) input), inputlen,
                              outbuf,
                              (uint8_t *) PyString_AsString((PyObject*) password), passwordlen,
                              maxmem, maxmemfrac, maxtime);
    Py_END_ALLOW_THREADS;

    Py_DECREF(password);
    Py_DECREF(input);

    PyObject *value = NULL;
    if (errorcode != 0) {
        PyErr_Format(ScryptError, "%s", g_error_codes[errorcode]);
        PyErr_SetNone(ScryptError);
    } else {
        value = Py_BuildValue("z#", outbuf, inputlen+128);
    }
    PyMem_Free(outbuf);

    return value;
}

static PyObject *scrypt_decrypt(PyObject *self, PyObject *args, PyObject* kwargs) {
    PyStringObject *input, *password;
    size_t inputlen, outputlen, passwordlen;
    int errorcode;
    size_t maxmem = g_maxmem_default;
    double maxmemfrac = g_maxmemfrac_default;
    double maxtime = g_maxtime_default;
    uint8_t *outbuf;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "SS|dnd", g_kwlist,
                                     &input, &password,
                                     &maxtime, &maxmem, &maxmemfrac)) {
        return NULL;
    }

    Py_INCREF(input);
    Py_INCREF(password);

    inputlen = PyString_Size((PyObject*) input);
    passwordlen = PyString_Size((PyObject*) password);

    outbuf = PyMem_Malloc(inputlen);

    Py_BEGIN_ALLOW_THREADS;
    errorcode = scryptdec_buf((uint8_t *) PyString_AsString((PyObject *) input), inputlen,
                              outbuf, &outputlen,
                              (uint8_t *) PyString_AsString((PyObject *) password), passwordlen,
                              maxmem, maxmemfrac, maxtime);
    Py_END_ALLOW_THREADS;

    Py_DECREF(password);
    Py_DECREF(input);

    PyObject *value = NULL;
    if (errorcode != 0) {
        PyErr_Format(ScryptError, "%s", g_error_codes[errorcode]);
    } else {
        value = Py_BuildValue("z#", outbuf, outputlen);
    }
    PyMem_Free(outbuf);
    return value;
}

static PyObject *scrypt_hash(PyObject *self, PyObject *args, PyObject* kwargs) {
    PyStringObject *password,   *salt;
    size_t          passwordlen, saltlen;
    int paramerror, hasherror;
    uint64_t N = 1024;
    uint32_t r = 1;
    uint32_t p = 1;
    uint8_t *outbuf;
    size_t   outbuflen;

    static char *g2_kwlist[] = {"password", "salt", "N", "r", "p", NULL};

    // note, this assumes uint32_t is unsigned long (k)
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "SS|Kkk", g2_kwlist,
                                                             &password, &salt,
                                                             &N, &r, &p)) {
        return NULL;
    }

    Py_INCREF(password);
    Py_INCREF(salt);

    passwordlen = PyString_Size((PyObject*) password);
    saltlen = PyString_Size((PyObject*) salt);

    // note, output buffer must be less than (2^32-1) * 32
    outbuf = PyMem_Malloc(64);
    outbuflen = 64;

    Py_BEGIN_ALLOW_THREADS;

    if ( r * p >= (1 << 30) || N <= 1 || (N & (N-1)) != 0) {
        paramerror = -1;
    } else {
        paramerror = 0;
        hasherror = crypto_scrypt((uint8_t *) PyString_AsString((PyObject *) password), passwordlen,
                                  (uint8_t *) PyString_AsString((PyObject *) salt),     saltlen,
                                  N, r, p,
                                  outbuf, outbuflen);
    }

    Py_END_ALLOW_THREADS;

    Py_DECREF(password);
    Py_DECREF(salt);

    PyObject *value = NULL;
    if (paramerror != 0) {
        PyErr_Format(ScryptError, "%s",
            "hash parameters are wrong (r*p should be < 2**30, and N should be a power of two > 1)");
    } else {
        if (hasherror != 0) {
            PyErr_Format(ScryptError, "%s", "could not compute hash");
        } else {
            value = Py_BuildValue("z#", outbuf, outbuflen);
        }
    }
    PyMem_Free(outbuf);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "encrypt", (PyCFunction) scrypt_encrypt, METH_VARARGS | METH_KEYWORDS,
      "encrypt(input, password, maxtime=5.0, maxmem=0, maxmemfrac=0.125): str; encrypt a string" },
    { "decrypt", (PyCFunction) scrypt_decrypt, METH_VARARGS | METH_KEYWORDS,
      "decrypt(input, password, maxtime=300.0, maxmem=0, maxmemfrac=0.5): str; decrypt a string" },
    { "hash", (PyCFunction) scrypt_hash, METH_VARARGS | METH_KEYWORDS,
      "hash(password, salt, N=2**14, r=8, p=1): str; compute a 64-byte scrypt hash" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initscrypt(void) {
    PyObject *m = Py_InitModule("scrypt", ScryptMethods);

    if (m == NULL) {
        return;
    }

    ScryptError = PyErr_NewException("scrypt.error", NULL, NULL);
    Py_INCREF(ScryptError);
    PyModule_AddObject(m, "error", ScryptError);
}
