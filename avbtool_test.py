#!/usr/bin/env python

# Copyright 2019, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""Unit tests for avbtool."""

# pylint: disable=unused-import
from __future__ import print_function

import unittest

import avbtool

class AvbtoolTest(unittest.TestCase):

  def _validate_icp_header(self, algorithm, icp_count):
    """Validate an ICP header structure and attempt to validate it.

    Arguments:
      algorithm: The algorithm to be used.
      icp_count: Number of ICPs that follow the ICP header.

    Returns:
      True if the ICP header validates; otherwise False.
    """
    icp_header = avbtool.AvbIcpHeader()
    icp_header.algorithm = algorithm
    icp_header.icp_count = icp_count
    return icp_header.is_valid()

  def _validate_icp_entry(self, log_url_size, leaf_index, signed_root_blob_size,
                          proof_hash_count, proof_size, next_entry):
    """Create an ICP entry structure and attempt to validate it.

    Returns:
      True if the tests pass, False otherwise.
    """
    icp_entry = avbtool.AvbIcpEntry()
    icp_entry.log_url_size = log_url_size
    icp_entry.leaf_index = leaf_index
    icp_entry.signed_root_blob_size = signed_root_blob_size
    icp_entry.proof_hash_count = proof_hash_count
    icp_entry.proof_size = proof_size
    icp_entry.next_entry = next_entry
    return icp_entry.is_valid()

  def test_default_icp_header(self):
    """Tests default ICP header structure."""
    icp_header = avbtool.AvbIcpHeader()
    self.assertTrue(icp_header.is_valid())

  def test_valid_icp_header(self):
    """Tests valid ICP header structures."""
    # 1 is SHA256/RSA4096
    self.assertTrue(self._validate_icp_header(algorithm=1, icp_count=4))

  def test_invalid_icp_header(self):
    """Tests invalid ICP header structures."""
    self.assertFalse(self._validate_icp_header(algorithm=-12, icp_count=4))
    self.assertFalse(self._validate_icp_header(algorithm=4, icp_count=-34))
    self.assertFalse(self._validate_icp_header(algorithm=10, icp_count=10))

  def test_empty_icp_entry(self):
    """Tests empty ICP entry structure."""
    icp_entry = avbtool.AvbIcpEntry()
    self.assertTrue(icp_entry.is_valid())

  def test_valid_icp_entry(self):
    """Tests valid ICP entry structures."""
    self.assertTrue(self._validate_icp_entry(
        log_url_size=28, leaf_index=2, signed_root_blob_size=92,
        proof_hash_count=2, proof_size=64, next_entry=0))
    self.assertTrue(self._validate_icp_entry(
        log_url_size=28, leaf_index=4, signed_root_blob_size=160,
        proof_hash_count=4, proof_size=128, next_entry=1))

  def test_invalid_icp_entry(self):
    """Tests invalid ICP entry structures."""
    self.assertFalse(self._validate_icp_entry(
        log_url_size=-2, leaf_index=2, signed_root_blob_size=92,
        proof_hash_count=2, proof_size=64, next_entry=0))
    self.assertFalse(self._validate_icp_entry(
        log_url_size=28, leaf_index=-1, signed_root_blob_size=92,
        proof_hash_count=2, proof_size=64, next_entry=0))
    self.assertFalse(self._validate_icp_entry(
        log_url_size=28, leaf_index=2, signed_root_blob_size=-2,
        proof_hash_count=2, proof_size=64, next_entry=0))
    self.assertFalse(self._validate_icp_entry(
        log_url_size=28, leaf_index=2, signed_root_blob_size=92,
        proof_hash_count=4, proof_size=128, next_entry=32234))


if __name__ == '__main__':
  unittest.main(verbosity=2)
