# Go Bindings for chikvdf

This module depends on cgo and c bindings from chikvdf. To compile, you will need to provide paths to the libraries to
link against.

This example links gmp statically so the destination system doesn't need to have it installed:

```shell
# This path needs to include the c_wrapper.h file from chikvdf's c_bindings
export CGO_CFLAGS="-I/path/to/chikvdf/src/c_bindings"
export CGO_LDFLAGS="-L/path/to/chikvdf/build/lib/static -L/opt/homebrew/opt/gmp/lib /opt/homebrew/opt/gmp/lib/libgmp.a"
```

You can also dynamically link against gmp if the target system has it installed and available at runtime

```shell
# This path needs to include the c_wrapper.h file from chikvdf's c_bindings
export CGO_CFLAGS="-I/path/to/chikvdf/src/c_bindings"
export CGO_LDFLAGS="-L/path/to/chikvdf/build/lib/static -L/opt/homebrew/opt/gmp/lib -lgmp"
```
