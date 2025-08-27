#!/bin/bash
#set -x

BINDIR=~/Downloads/binaries
PATCHED_SGXS_INFO=~/rust-sgx/target/debug/sgxs-info

assert_eq() {
	if [[ ! $1 == $2 ]]; then
    	    echo -e "\tL__ FAIL: $3 differ"
	else
	    echo -e "\tL__ OK: $3 match"
	fi
}

extract_sum() {
	sha256sum $1 | sed 's/\s.*$//'
}

check_eq_file() {
	co=$(cmp $1 $2)
	if [[ -z $co ]]; then
	    echo -e "\tL__ OK: $1 $2 match"
	else
    	    echo -e "\tL__ $3: $co"
	fi
}

assert_eq_file() {
	check_eq_file $1 $2 "FAIL"
}

warn_eq_file() {
	check_eq_file $1 $2 "WARN"
}

openssl genrsa -3 3072 > private.pem

for b in $BINDIR/*.dump; do
	if [[ -e $b.sgxs ]]; then
		continue
	fi

	echo -e "\n.. converting $b"
	base=${b%.*}
	./dump2sgxs.py $b $base.json > $base.dump2sgxs.log
	size_orig=$(ls -lhH $b | awk '{print $5}')
	size_sgxs=$(ls -lh $b.sgxs | awk '{print $5}')
	echo -e "\tL__ OK: reduced $size_orig (dump) to $size_sgxs (sgxs)"

	# NOTE: some runtimes (gotee) may produce non-identical dumps in the
	# _unmeasured_ areas (sgx-trace copied those from application
	# memory, as they are provided to EADD, whereas their contents is
	# ommitted and always zero-initialized in sgxs-created enclaves)
	warn_eq_file $b $b.zero

	# save sgxs-info stats
	sgxs-info summary $b.sgxs > $base.sgxs-summary
	sgxs-info list-pages $b.sgxs > $base.sgxs-pages

	# NOTE: sgxs-info contained a bug that did not always write the full dump
    	if [[ ! $size_orig =~ 'G' ]]; then
		$PATCHED_SGXS_INFO dump-mem $b.sgxs > $base.sgxs-dump
		assert_eq_file $base.sgxs-dump $b.zero
	else
		echo -e "\tL__ WARN: skipping sgxs-info dump creation ($size_orig file too large)"
	fi

	# sanity check: load converted sgxs and compare dump and mrenclave
	sgxs-sign --key private.pem $b.sgxs $b.sigstruct >/dev/null 2>&1
	./sgx-trace sgxs-load $b.sgxs $b.sigstruct > $base.sgxs-load.ptrace.log
	mrenclave=$(cat $base.sgxs-load.ptrace.log | sed -n -e 's/^.*MRENCLAVE: //p')
	echo -e "\tL__ OK: loaded with MRENCLAVE=$mrenclave"
	assert_eq $mrenclave $(extract_sum $b.sgxs) "sha256sum $b.sgxs mrenclave"
	assert_eq_file $b.sgxs enclave0.sgxs
	assert_eq_file $b.zero enclave0.dump
done

rm -Rf *.pem enclave0.*
rm -Rf $BINDIR/*.sigstruct $BINDIR/*.dump.zero $BINDIR/*.sgxs-dump
