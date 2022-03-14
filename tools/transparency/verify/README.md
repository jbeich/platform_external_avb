# Pixel Factory Image Verifier

Binary `verifier` verifies that a particular image, identified by its
`{build_fingerprint, vbmeta_digest}` (the log payload) is included in a
tamper-evident log of Pixel Factory Images. To do so, it checks that this
payload is contained as a leaf of the Merkle tree that implements the
tamper-evident log, at the specified leaf index.

This tool lives in
https://android.googlesource.com/platform/external/avb/+/master/tools/transparency/
and be runnable by external/public. We develop it here for now and will migrate
it over once the tool is complete.

## Usage

### Setting up a test server

If you need to test against specific test tiles, you can run a test server.

Start a HTTP server to host the tiles. For example:

```bash
$ cd /google/src/head/depot/google3/experimental/users/nataliedoduc/pixelBT/testing/export/20211025
$ python3 -m http.server
```

### Running the verification tool

#### Verifying the prod Binary Transparency for Pixel log

From a google3/ CitC directory, run the following.

```bash
$ blaze run wireless/android/security/transparency/verify/cmd/verifier:verifier -- \
  --image_info_index=0 \
  --payload_path=/google/src/head/depot/google3/experimental/users/nataliedoduc/pixelBT/testing/payload/prod_log_leaf_0.txt
```

Note: With `blaze run`, you need to pass the full absolute path to the payload,
as per the example.

You can vary the leaf to verify in the [0, logSize] range, by changing
leaf_index and payload_path. You can construct your own payload following the
instructions on
https://developers.devsite.corp.google.com/android/binary_transparency/pixel.

Details of the Binary Transparency for Pixel log are:

-   Log Size:
    https://developers.google.com/android/binary_transparency/checkpoint.txt
-   Leaves:
    https://developers.google.com/android/binary_transparency/image_info.txt
