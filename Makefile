ifneq ($(wildcard /dev/sgx_enclave),) 
    DRV = -DIN_KERNEL_DRV=1
else ifneq ($(wildcard /dev/isgx),) 
    DRV = -DISGX_DRV=1
endif

# Build statically without shared libraries to be able to use in Docker
# container (e.g., SCONE)
CFLAGS += -static $(DRV)

sgx-tracer: sgx-tracer.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f sgx-tracer
