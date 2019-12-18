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
"""Integration tests for avbtool with AFTL."""

import os
import unittest

import avbtool

class AvbtoolIntegrationTest(unittest.TestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AvbtoolIntegrationTest, self).setUp()
    self.avbtool = avbtool.Avb()
    self.output_file = open('vbmeta_icp.img', 'wb')
    self.aftl_host_port = os.environ['AFTL_HOST']
    self.aftl_pub_key = 'transparency_key2.pub'
    self.make_icp_default_params = {
        'vbmeta_image_path': 'vbmeta.img',
        'output': self.output_file,
        'algorithm': 'SHA256_RSA4096',
        'signing_helper': None,
        'signing_helper_with_files': None,
        'version_incremental': '1',
        'transparency_log_servers': [self.aftl_host_port],
        'transparency_log_pub_keys': [self.aftl_pub_key],
        'manufacturer_key': 'manufacturer_key_4096.rsa',
        'padding_size': 0
    }

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    self.output_file.close()
    super(AvbtoolIntegrationTest, self).tearDown()

  def _read_icp_from_vbmeta_blog(self):
    self.output_file.seek(0)
    image = avbtool.ImageHandler(self.output_file.name)

    (footer, header, _, _) = self.avbtool._parse_image(image)
    offset = 0
    if footer:
      offset = footer.vbmeta_offset
    image.seek(offset)
    vbmeta_blob = image.read(header.SIZE +
                             header.authentication_data_block_size +
                             header.auxiliary_data_block_size)
    image.seek(offset + len(vbmeta_blob))
    icp_bytes = image.read(100000)
    return icp_bytes

  def test_make_icp_with_one_transparency_log(self):
    """Tests integration of avbtool with one AFTL."""
    # Submits vbmeta to AFTL and fetches ICP.
    result = self.avbtool.make_icp_from_vbmeta(**self.make_icp_default_params)
    self.assertTrue(result)
    icp_bytes = self._read_icp_from_vbmeta_blog()
    self.assertGreater(len(icp_bytes), 0)

    # Checks ICP proof blob for correctness.
    icp_blob = avbtool.AvbIcpBlob(icp_bytes)
    self.assertTrue(icp_blob.is_valid())

    icp_header = icp_blob.icp_header
    self.assertIsNotNone(icp_header)
    self.assertEqual(icp_header.magic, 'AFTL')
    self.assertEquals(icp_header.icp_count, 1)

    self.assertEquals(len(icp_blob.icp_entries), 1)
    for icp in icp_blob.icp_entries:
      self.assertEqual(icp.log_url, self.aftl_host_port)
      self.assertTrue(icp.verify_icp('transparency_key2.pub'))

  def test_make_icp_with_two_transparency_log(self):
    """Tests integration of avbtool with one AFTL."""
    # Submits vbmeta to AFTL and fetches ICP.
    self.make_icp_default_params['transparency_log_servers'] = [
        self.aftl_host_port, self.aftl_host_port]
    self.make_icp_default_params['transparency_log_pub_keys'] = [
        self.aftl_pub_key, self.aftl_pub_key]

    result = self.avbtool.make_icp_from_vbmeta(**self.make_icp_default_params)
    self.assertTrue(result)
    icp_bytes = self._read_icp_from_vbmeta_blog()
    self.assertGreater(len(icp_bytes), 0)

    # Checks ICP proof blob for correctness.
    icp_blob = avbtool.AvbIcpBlob(icp_bytes)
    self.assertTrue(icp_blob.is_valid())

    icp_header = icp_blob.icp_header
    self.assertIsNotNone(icp_header)
    self.assertEqual(icp_header.magic, 'AFTL')
    self.assertEquals(icp_header.icp_count, 2)

    self.assertEquals(len(icp_blob.icp_entries), 2)
    for icp in icp_blob.icp_entries:
      self.assertEqual(icp.log_url, self.aftl_host_port)
      self.assertTrue(icp.verify_icp('transparency_key2.pub'))


if __name__ == '__main__':
  unittest.main()
