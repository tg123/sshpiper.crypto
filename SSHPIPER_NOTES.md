# SSHPiper Fork Notes

This is a fork of golang.org/x/crypto maintained for use with SSHPiper.

## Version History

### v0.45.0-sshpiper-20251122
- Rebased sshpiper functionality onto upstream v0.45.0
- Added sshpiper.go and sshpiper_test.go to ssh package
- Added knownhosts reader functionality

### v0.43.0-sshpiper-20251012
- Initial sshpiper functionality based on upstream v0.43.0

## Customizations

The following files have been added to support SSHPiper:
- `ssh/sshpiper.go` - Main SSHPiper functionality
- `ssh/sshpiper_test.go` - Tests for SSHPiper
- `ssh/knownhosts/reader.go` - Helper for reading known hosts from io.Reader
- `ssh/knownhosts/reader_test.go` - Tests for knownhosts reader

All other code is from the upstream golang.org/x/crypto repository.
