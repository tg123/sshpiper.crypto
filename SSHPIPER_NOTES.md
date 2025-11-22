# SSHPiper Fork Notes

This is a fork of golang.org/x/crypto maintained for use with SSHPiper.

## Version History

### v0.45.0-sshpiper-20251122
- Rebased sshpiper functionality onto upstream v0.45.0
- All 11 sshpiper tests passing
- 49 upstream files updated from v0.43.0 to v0.45.0
- Added sshpiper.go and sshpiper_test.go to ssh package
- Added knownhosts reader functionality
- Full compatibility with upstream golang.org/x/crypto v0.45.0

### v0.43.0-sshpiper-20251012
- Initial sshpiper functionality based on upstream v0.43.0

## Customizations

The following files have been added to support SSHPiper:
- `ssh/sshpiper.go` - Main SSHPiper functionality (736 lines)
- `ssh/sshpiper_test.go` - Tests for SSHPiper (915 lines, 11 test functions)
- `ssh/knownhosts/reader.go` - Helper for reading known hosts from io.Reader (21 lines)
- `ssh/knownhosts/reader_test.go` - Tests for knownhosts reader (17 lines)

All other code is from the upstream golang.org/x/crypto repository.

## Upstream

Upstream repository: https://github.com/golang/crypto
Current upstream version: v0.45.0
