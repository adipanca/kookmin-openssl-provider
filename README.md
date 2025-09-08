# Kookmin OpenSSL Provider — Quick Start (English)

This guide walks you through building **OpenSSL 3.0**, **liboqs**, and the **kookmin-openssl-provider**, then verifying ML‑DSA (sign) and ML‑KEM (KEM) with simple tests.

> **Prefixes used in this guide**
>
> - OpenSSL prefix: `/opt/openssl-master`
> - liboqs prefix: `/opt/liboqs`
>
> Your distro may use `lib64` instead of `lib`. Adjust paths accordingly wherever you see `lib` (e.g., `.../lib/ossl-modules` → `.../lib64/ossl-modules`).

---

## 0) Install build tools

```bash
sudo apt update
sudo apt install -y build-essential perl git libssl-dev cmake automake libtool gcc tree
```

---

## 1) Build & install OpenSSL 3.0

```bash
git clone --branch openssl-3.0 https://github.com/openssl/openssl.git
cd ~/openssl

./config --prefix=/opt/openssl-master --openssldir=/opt/openssl-master/ssl \
  shared enable-fips enable-tls1_3

make -j"$(nproc)"
sudo make install

# Environment (shell init)
echo 'export PATH="/opt/openssl-master/bin:$PATH"' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH="/opt/openssl-master/lib:$LD_LIBRARY_PATH"' >> ~/.bashrc
source ~/.bashrc

# For the current shell too
export PATH="/opt/openssl-master/bin:$PATH"
export LD_LIBRARY_PATH="/opt/openssl-master/lib:$LD_LIBRARY_PATH"

openssl version
```

---

## 2) Build & install liboqs

```bash
cd ~
git clone https://github.com/open-quantum-safe/liboqs.git
cd ~/liboqs
rm -rf build
mkdir build && cd build

cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_DIST_BUILD=ON \
  -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
  -DOQS_ENABLE_KEM_KYBER=ON \
  -DOQS_ENABLE_KEM_NTRUPRIME=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/opt/openssl-master \
  -DOPENSSL_LIBRARIES=/opt/openssl-master/lib \
  -DOPENSSL_INCLUDE_DIR=/opt/openssl-master/include

make -j"$(nproc)"
sudo make install
```

Tell the dynamic linker where to find `liboqs.so`:

```bash
echo "/opt/liboqs/lib" | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
ldconfig -p | grep liboqs   # you should see liboqs entries
```

---

## 3) Build & install the provider

```bash
git clone https://github.com/adipanca/kookmin-openssl-provider.git
cd ~/kookmin-openssl-provider

rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/opt/openssl-master \
  -DCMAKE_INSTALL_PREFIX=/opt/openssl-master \
  -DCMAKE_INSTALL_LIBDIR=lib   # use 'lib64' if your system uses lib64

cmake --build build -j
sudo cmake --install build

# Verify the module is in OpenSSL’s module dir (adjust lib vs lib64)
ls -l /opt/openssl-master/lib/ossl-modules/kookminlib.so
```

---

## 4) (Optional) Configure `openssl.cnf` for auto-loading

Edit the config file:

```bash
sudo nano /opt/openssl-master/ssl/openssl.cnf
```

Add (or merge) the following blocks:

```ini
[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Groups = MLKEM512:MLKEM768:MLKEM1024

[provider_sect]
default = default_sect
kookminlib = kookminlib_sect

[kookminlib_sect]
activate = 1
identity = kookminlib
# Set the correct path; use lib or lib64 as installed on your system
path = /opt/openssl-master/lib/ossl-modules/kookminlib.so
# module = kookminlib.so  # (alternative style)

[default_sect]
activate = 1
```

> If you don’t edit `openssl.cnf`, you can still load the provider by setting `OPENSSL_MODULES` (see below).

---

## 5) Verify at the CLI

If you didn’t edit `openssl.cnf`, set the module path for your current shell:

```bash
export OPENSSL_MODULES=/opt/openssl-master/lib/ossl-modules  # or lib64/ossl-modules
```

List providers and algorithms:

```bash
/opt/openssl-master/bin/openssl list -providers -provider default -provider kookminlib

/opt/openssl-master/bin/openssl list -signature-algorithms \
  -provider default -provider kookminlib

/opt/openssl-master/bin/openssl list -kem-algorithms \
  -provider default -provider kookminlib

/opt/openssl-master/bin/openssl list -key-managers \
  -provider default -provider kookminlib
```

You should see `mldsa44`, `mldsa65`, `mldsa87` under signatures, and `MLKEM512`, `MLKEM768`, `MLKEM1024` under KEMs.

---

## 6) Run the tests

> Ensure `OPENSSL_MODULES` points to your modules directory:
>
> ```bash
> export OPENSSL_MODULES=/opt/openssl-master/lib/ossl-modules
> ```

### Signature (ML‑DSA 44/65/87)

```bash
cd ~/kookmin-openssl-provider/tests

cc test_sig.c -o test_sig \
  -I/opt/openssl-master/include \
  -L/opt/openssl-master/lib -lcrypto \
  -Wl,-rpath,/opt/openssl-master/lib

./test_sig
# Expected output (pure sign/verify):
# [mldsa44] pure verify -> 1 (1=ok)
# [mldsa65] pure verify -> 1 (1=ok)
# [mldsa87] pure verify -> 1 (1=ok)
```

> **Note:** This provider currently supports **pure** sign/verify (`EVP_PKEY_sign/verify`) for ML‑DSA. Digest-based flows (`EVP_DigestSign*`) are intentionally not used in the test.

### KEM (ML‑KEM 512/768/1024)

```bash
export OPENSSL_MODULES=/opt/openssl-master/lib/ossl-modules

cc test_kem.c -o test_kem \
  -I/opt/openssl-master/include \
  -L/opt/openssl-master/lib -lcrypto \
  -Wl,-rpath,/opt/openssl-master/lib

./test_kem
# Expected output:
# [MLKEM512]  KEM OK: shared secret match (ctlen=..., seclen=32)
# [MLKEM768]  KEM OK: shared secret match (ctlen=..., seclen=32)
# [MLKEM1024] KEM OK: shared secret match (ctlen=..., seclen=32)
```

---

## Troubleshooting

- **`liboqs.so.*: not found`**
  - Re-run `sudo ldconfig` and confirm `ldconfig -p | grep liboqs` shows entries.
  - Ensure `/opt/liboqs/lib` is present in `/etc/ld.so.conf.d/liboqs.conf`.

- **Provider not found / algorithms missing**
  - Make sure `OPENSSL_MODULES` points to the directory where `kookminlib.so` was installed.
  - Ensure you’re using the OpenSSL you just installed: `/opt/openssl-master/bin/openssl` and `/opt/openssl-master/lib` are first in PATH/LD_LIBRARY_PATH.

- **`mldsa*` digest sign fail**
  - Use **pure** `EVP_PKEY_sign/verify` (as in the provided test). Digest-based flows aren’t used here.

- **lib vs lib64**
  - Some distros use `lib64`. Keep paths consistent across:
    - `CMAKE_INSTALL_LIBDIR`
    - `openssl.cnf` (`path = .../ossl-modules/kookminlib.so`)
    - `OPENSSL_MODULES`
    - Linker rpath in test commands

---

## Acknowledgements

- [OpenSSL](https://github.com/openssl/openssl)
- [Open Quantum Safe (liboqs)](https://github.com/open-quantum-safe/liboqs)

---

## License

See the repository’s `LICENSE` (if provided) for licensing terms of this provider. OpenSSL and liboqs are licensed under their respective licenses.