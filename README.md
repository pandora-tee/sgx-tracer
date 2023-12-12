# SGX-Tracer

`sgx-tracer` is a simple C program that uses common Linux `ptrace` functionality to intercept the Intel SGX driver while an application loads an enclave. These intercepted calls are used to create the exact memory dump of an enclave at creation time, allowing Pandora to *truthfully* validate enclave shielding runtimes. 

A general note: 
1. If ptrace is used, Docker containers need the additional flag `--cap-add=SYS_PTRACE`. Thus, add this to your docker run command if you wish to use sgx-tracer!
2. sgx-tracer uses linux headers, so make sure they are installed when building.

## Usage

`sgx-tracer` simply wraps around your enclave call. Just execute your untrusted program as normal and put `sgx-tracer` before it.

```bash
make
./sgx-tracer <command to run the enclave with its arguments>
```

`sgx-tracer` will then dump the memory during enclave creation time and generate a `.dump` file with the raw memory and a `.json` file with metadata that contains relevant information such as the SECS.

## Troubleshooting

Some enclaves don't like to be ptrace'd and may crash or never complete. This should never be a problem however, since `sgx-tracer` works during enclave creation which does not require the enclave to complete its execution. Just kill the enclave after the dump succeeded and use the enclave dump in Pandora.