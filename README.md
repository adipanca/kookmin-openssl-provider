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
# Ensure your provider is visible
export OPENSSL_MODULES=/opt/openssl-master/lib64/ossl-modules   # or lib/ossl-modules

# 1) Create server.cnf with SAN
cat > server.cnf <<'EOF'
[ req ]
distinguished_name = dn
x509_extensions = req_ext
prompt = no

[ dn ]
CN = localhost

[ req_ext ]
subjectAltName = @alt
extendedKeyUsage = serverAuth
keyUsage = digitalSignature
basicConstraints = CA:FALSE

[ alt ]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

# 2) Generate server key
/opt/openssl-master/bin/openssl ecparam -name prime256v1 -genkey -noout -out server.key

# 3) Generate CSR
/opt/openssl-master/bin/openssl req -new -key server.key -out server.csr -config server.cnf

# 4) Sign with your CA
/opt/openssl-master/bin/openssl x509 -req -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 \
  -extfile server.cnf -extensions req_ext

# 5) Verify SAN
/opt/openssl-master/bin/openssl x509 -in server.crt -noout -text | grep -A2 "Subject Alternative Name"

# 6) Run TLS server (hybrid KEM group)
/opt/openssl-master/bin/openssl s_server \
  -provider kookminlib -provider default \
  -accept 4433 -www \
  -cert server.crt -key server.key \
  -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 \
  -groups X25519MLKEM768

# 7) Test with OpenSSL client
/opt/openssl-master/bin/openssl s_client \
  -provider kookminlib -provider default \
  -connect localhost:4433 -tls1_3 \
  -ciphersuites TLS_AES_256_GCM_SHA384 \
  -groups X25519MLKEM768 -msg -state

# 8) Trust your CA (system-wide)
sudo cp ca.crt /usr/local/share/ca-certificates/local-test-ca.crt
sudo update-ca-certificates --fresh

# 9) Add CA to Chrome’s NSS DB
mkdir -p "$HOME/.pki/nssdb"
certutil -N -d sql:$HOME/.pki/nssdb --empty-password 2>/dev/null || true
certutil -A -d sql:$HOME/.pki/nssdb -t "C,," -n "Local Test CA" -i ca.crt
certutil -L -d sql:$HOME/.pki/nssdb | grep "Local Test CA"


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