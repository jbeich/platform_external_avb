#!/usr/bin/env python
#
# Copyright 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""TODO(bryanhenry): DO NOT SUBMIT without one-line documentation for at_write_persistent_digest.

TODO(bryanhenry): DO NOT SUBMIT without a detailed description of
at_write_persistent_digest.
"""

import sys

ver = sys.version_info
if (ver[0] < 2) or (ver[0] == 2 and ver[1] < 7) or (ver[0] == 3 and ver[1] < 2):
  print('This script requires Python 2.7+ or 3.2+')
  sys.exit(1)

import argparse
import os
import shutil
import struct
import subprocess
import tempfile

HELP_DESCRIPTION = """Helper script for 'fastboot oem
at-write-persistent-digest' that generates and stages the required input data
format."""

AVB_PERSISTENT_DIGEST_PREFIX = 'avb.persistent_digest.'


def WritePersistentDigest(name,
                          digest=None,
                          clear_digest=False,
                          serial=None,
                          verbose=False):
  if not name.startswith(AVB_PERSISTENT_DIGEST_PREFIX):
    print("Automatically adding '{}' prefix to persistent value name".format(
        AVB_PERSISTENT_DIGEST_PREFIX))
    name = AVB_PERSISTENT_DIGEST_PREFIX + name

  tempdir = tempfile.mkdtemp()
  try:
    digest_data = os.path.join(tempdir, 'digest_data')

    with open(digest_data, 'wb') as out:
      out.write(struct.pack('<I', len(name)))
      out.write(name)
      if clear_digest:
        out.write(struct.pack('<I', 0))
      else:
        digest_bytes = bytearray.fromhex(digest)
        out.write(struct.pack('<I', len(digest_bytes)))
        out.write(digest_bytes)

    def fastboot_cmd(args):
      args = ['fastboot'] + (['-s', serial] if serial else []) + args
      if verbose:
        print('$ ' + ' '.join(args))

      try:
        out = subprocess.check_output(
            args, stderr=subprocess.STDOUT).decode('utf-8')
      except subprocess.CalledProcessError as e:
        print(e.output.decode('utf-8'))
        print("Command '{}' returned non-zero exit status {}".format(
            ' '.join(e.cmd), e.returncode))
        sys.exit(1)

      if verbose:
        print(out)
      return out

    fastboot_cmd(['stage', digest_data])
    fastboot_cmd(['oem', 'at-write-persistent-digest'])

    print("Persistent value '{}' {}".format(
        name, 'cleared' if clear_digest else 'written'))
    return 0

  finally:
    shutil.rmtree(tempdir)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description=HELP_DESCRIPTION)

  # Optional arguments
  parser.add_argument(
      '-v',
      '--verbose',
      action='store_true',
      help='verbose; prints fastboot commands and their output')
  parser.add_argument(
      '-s',
      '--serial',
      help=
      "specify device to unlock, either by serial or any other valid value for fastboot's -s arg"
  )

  # Required arguments
  parser.add_argument(
      '--name',
      required=True,
      help=
      "persistent digest name to write, 'avb.persistent_digest.' prefix will be automatically added if not already present"
  )
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument(
      '--clear_digest',
      action='store_true',
      help=
      'clear any existing persistent digest value, rather than writing a new value'
  )
  group.add_argument(
      '--digest',
      help='persistent digest value to write, as a hex encoded string')

  # Print help if no args given
  args = parser.parse_args(args=None if sys.argv[1:] else ['-h'])

  sys.exit(
      WritePersistentDigest(
          name=args.name,
          clear_digest=args.clear_digest,
          digest=args.digest,
          serial=args.serial,
          verbose=args.verbose))
