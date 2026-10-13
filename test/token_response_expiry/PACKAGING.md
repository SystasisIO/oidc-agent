# Separate packaging change: pkg-config metadata

This is an additive Makefile packaging change, separate from the token expiry
fix. It does not port the build to CMake, change the C ABI/SONAME or manage daemon
lifecycle. `lib/liboidc-agent.pc.in` is the maintained template; `make pkgconfig`
generates `lib/api/liboidc-agent.pc` from the actual `VERSION`, `PREFIX`,
`LIBDEV_PATH` and `INCLUDE_PATH`. `make install_lib-dev` now also installs it at
`$(PKGCONFIG_PATH)/liboidc-agent.pc`, defaulting to `$(LIBDEV_PATH)/pkgconfig`.
`install_pkgconfig` installs metadata alone. `uninstall_libdev` removes it.
Generated files remain under the already ignored `lib/api` tree.

Metadata is regenerated when requested, so changing installation paths or a
command-line VERSION override cannot silently reuse an older `.pc`. The fork's
default VERSION is `5.3.8-systasis.1`. It is not a manually supplied discovery
file. `Requires.private: libsodium` and optional cJSON/list linker flags describe
static client dependencies; shared consumers use `-loidc-agent`. Public headers
are found through the existing include root, e.g. `<oidc-agent/api.h>`.

## Targeted Linux build and installation

Use the coordinator's isolated **source copy**, not the vendor checkout.
Besides the focused test dependencies, the targeted agent/library build needs
libsodium, libqrencode and GLib development packages. On Debian/Ubuntu:

```sh
apt-get install build-essential pkg-config libcurl4-openssl-dev libsodium-dev \
  libmicrohttpd-dev libqrencode-dev libglib2.0-dev
```

Bundled cJSON/list/mustache are selected below. No prompt/UI, man pages, full
`all` target or daemon startup is requested. Upstream's Makefile can still print
unrelated GTK/WebKit discovery warnings during parse; these targeted C builds
do not require the UI target. The compiler shown is the coordinator's installed
Linux toolchain, not a dependency introduced by this packaging change.

Upstream's Linux `PREFIX` is also used for staging rather than a conventional
autoconf installation prefix. Explicitly set its existing install-path variables
to produce truthful metadata for a real custom prefix. Keep `LIB_PATH` and
`LIBDEV_PATH` equal for upstream's existing relative shared-library symlinks:

```sh
prefix=/opt/oidc-agent-systasis
cc=/opt/LLVM-22.1.8-Linux-ARM64/bin/clang
make -C /build/oidc-agent-patched -j4 CC="$cc" \
  PREFIX="$prefix" BIN_PATH="$prefix" BIN_AFTER_INST_PATH="$prefix" \
  LIB_PATH="$prefix/lib" LIBDEV_PATH="$prefix/lib" INCLUDE_PATH="$prefix/include" \
  USE_CJSON_SO=0 USE_LIST_SO=0 USE_MUSTACHE_SO=0 \
  bin/oidc-agent shared_lib lib/api/liboidc-agent.a pkgconfig

make -C /build/oidc-agent-patched -j4 CC="$cc" \
  PREFIX="$prefix" BIN_PATH="$prefix" BIN_AFTER_INST_PATH="$prefix" \
  LIB_PATH="$prefix/lib" LIBDEV_PATH="$prefix/lib" INCLUDE_PATH="$prefix/include" \
  USE_CJSON_SO=0 USE_LIST_SO=0 USE_MUSTACHE_SO=0 \
  install_lib-dev "$prefix/bin/oidc-agent"
```

Run the build and install commands serially. `install_lib-dev` is upstream's
existing complete developer install, including shared/static libraries and
public headers; the new prerequisite installs the generated `.pc`. To install
only metadata after an existing library installation, use the same variables
with the `install_pkgconfig` target instead.

The `.pc` paths above name their final installation, not a temporary staging
root. `DESTDIR` semantics are not newly introduced here; do not advertise paths
under an ephemeral build/staging directory to downstream consumers.

## Verify

```sh
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --validate liboidc-agent
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --modversion liboidc-agent
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --cflags --libs liboidc-agent
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --static --libs liboidc-agent
readelf -d "$prefix/lib/liboidc-agent.so.5.3.8-systasis.1"
"$prefix/bin/oidc-agent" --version
```

Expected metadata version: `5.3.8-systasis.1`; ELF SONAME:
`liboidc-agent.so.5`. Downstream exact package checks should require that full
version. Check the installed library and header paths in the emitted flags.

**A matching client package still does not prove the running daemon is patched.**
The installed daemon that actually serves the selected or forwarded socket must
be restarted from the patched binary. See [regression notes](README.md) for the
daemon boundary and focused RED/GREEN commands. No daemon/service lifecycle or
downstream discovery changes are implemented by this packaging addition.

The patch author did not run builds, installs or metadata generation. Those
commands and independent review remain coordinator-owned acceptance gates.
