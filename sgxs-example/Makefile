
all: eexit.sgxs

%.sgxs: %.S private.pem
	as -k $<
	objcopy -O binary -j .text a.out
	sgxs-build rx=a.out tcs=nssa:1 > $@
	sgxs-info summary $@
	sha256sum $@
	sgxs-sign $@ $@.sigstruct --key private.pem

private.pem:
	openssl genrsa -3 3072 > $@

clean:
	rm -Rf *.sgxs *.out *.pem *.sigstruct


