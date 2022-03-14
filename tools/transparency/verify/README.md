# Verifier of Binary Transparency for Pixel Factory Images

This repository contains code to read the transparency log for [Binary Transparency for Pixel Factory Images](https://developers.google.com/android/binary_transparency/pixel).

## Files and Directories
* `cmd/verifier/`
  * Contains the binary to read the transparency log. It is embedded with the public key of the log to verify log identity.
* `internal/`
  * Internal libraries for the verifier binary.

### Build
This module requires Go 1.17. Install [here](https://go.dev/doc/install), and run `go build cmd/verifier/verifier.go`. For further usage instructions, refer to https://developers.google.com/android/binary_transparency/pixel.
