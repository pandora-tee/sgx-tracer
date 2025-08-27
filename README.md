[![DOI](https://zenodo.org/badge/730334280.svg)](https://zenodo.org/doi/10.5281/zenodo.10390406)

# SGX-Tracer

`sgx-tracer` is a simple C program that uses common Linux `ptrace` functionality to intercept the Intel SGX driver while an application loads an enclave. These intercepted calls are used to create the exact memory dump of an enclave at creation time, allowing Pandora to *truthfully* validate enclave shielding runtimes. 

A general note: 
1. If ptrace is used, Docker containers need the additional flag `--cap-add=SYS_PTRACE`. Thus, add this to your docker run command if you wish to use sgx-tracer!
2. sgx-tracer uses linux headers, so make sure they are installed when building.

## Usage

`sgx-tracer` wraps around your enclave call. Just execute your untrusted program as normal and put `sgx-tracer` before it.

```bash
make
./sgx-tracer <command to run the enclave with its arguments>
```

`sgx-tracer` will then dump the memory during enclave creation time and generate a `.dump` file with the raw memory and a `.json` file with metadata that contains relevant information such as the SECS.  

Additionally, recent versions of `sgx-tracer` will output a `.sgxs` file containing the enclave in the canonical [SGXS format](https://github.com/fortanix/rust-sgx/blob/master/doc/SGXS.md), which is *much* smaller compared to `.dump` files (no unmeasured pages and unmapped regions). If needed, the `dump2sgxs.py` script in this repository can be used to convert older `.dump` files produced by `sgx-tracer` to the SGXS format.

## Working with the SGX stream format

`sgx-tracer` supports outputting enclaves in the standardized [SGX stream (SGXS)](https://github.com/fortanix/rust-sgx/blob/master/doc/SGXS.md) format. The SGXS format is the most basic description of an enclave, consisting _exactly_ of all data that would be hashed to produce the enclave attestation measurement MRENCLAVE. Following Intel's ISA specification, an `enclave.sgxs` file consists of an ordered series of records containing a 64-byte header, optionally followed by data, such that `sha256sum(enclave.sgxs)` produces MRENCLAVE.

Enclave dumps extracted by `sgx-tracer` in the SGXS format can be analyzed by other SGXS-compliant tools. Notably, the [`sgxs-tools`](https://github.com/fortanix/rust-sgx/tree/master/intel-sgx/sgxs-tools) Rust crate developed by Fortanix can be installed as follows:

```bash
$ cargo install sgxs-tools
```

This should make several `sgxs-*` command-line tools available, most importantly `sgxs-info` can be used to output the virtual address space of an SGXS enclave, list pages, or dump the memory content.

### Example usage

Load a minimal SGXS enclave using `sgxs-load` and extract the resulting enclave back into the SGXS format using `sgx-tracer`:

```bash
$ make -C sgxs-example
$ ./sgx-tracer sgxs-load sgxs-example/eexit.sgxs sgxs-example/eexit.sgxs.sigstruct 
```

Now, you can verify that the SHA256 sum of the extracted SGXS file indeed matches MRENCLAVE and inspect the enclave virtual layout:

```bash
$ sha256sum enclave0.sgxs 
6972ee47174d2bc74b98aa77107cec2c6ec20b30b88a8e8c1ba5af876c25067a  enclave0.sgxs
$ sgxs-info summary enclave0.sgxs 
   0- fff Reg  r-x  (data) meas=all
1000-1fff Tcs  ---  (data) meas=all [oentry=0x0, ossa=0x2000, nssa=1]
2000-2fff Reg  rw- (empty) meas=all
3000-3fff (unmapped)
```

If desired, the SGXS file can even be converted into a memory dump file and vice versa:

```bash
$ sgxs-info dump-mem enclave0.sgxs > sgxs-dump.dump
$ sha256sum sgxs-dump.dump enclave0.dump 
9dfca65bd743f069a59b6795b50ed6d8e682f74434a3f08e8535b97d14a01a7f  sgxs-dump.dump
9dfca65bd743f069a59b6795b50ed6d8e682f74434a3f08e8535b97d14a01a7f  enclave0.dump
$ ./dump2sgxs.py enclave0.dump enclave0.json
$ sha256sum enclave0.dump.sgxs 
6972ee47174d2bc74b98aa77107cec2c6ec20b30b88a8e8c1ba5af876c25067a  enclave0.dump.sgxs
```

## Troubleshooting

Some enclaves don't like to be ptrace'd and may crash or never complete. This should never be a problem however, since `sgx-tracer` works during enclave creation which does not require the enclave to complete its execution. Just kill the enclave after the dump succeeded and use the enclave dump in Pandora.
