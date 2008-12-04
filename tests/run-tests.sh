#!/bin/sh -e

if [ ! -x ../gad ] || [ ! -x ../permls ]; then
	echo "error: essential scripts not found, wrong directory?" >&2
	exit 1
fi

what=$1
if [ "$what" == "" ]; then
	# No test given, run all tests.
	for i in $(echo test_*); do
		if [ -d "$i" ]; then
			"$0" "$i"
		fi
	done
	exit 0
fi

# Check environment
if [ ! -e $what/conf ]; then
	echo "error: no configuration found for $what" >&2
	exit 1
fi
if [ ! -x $what/prepare ]; then
	echo "error: no executable preparation script found for $what" >&2
	exit 1
fi

# Prepare test directory
mkdir -p temp/$what
cd temp/$what
../../$what/prepare
../../../permls base > before

# Perform and record changes
../../../gad ../../$what/conf
../../../permls base > after

# Do we have reference?
if [ ! -e ../../$what/reference ]; then
	echo "notice: no reference found for $what, creating" >&2
	../../../permls base > ../../$what/reference
else
	# Compare with what we expected
	if ! diff -u ../../$what/reference after >/dev/null; then
		echo "$what: FAIL"
		while true; do
			echo -n "Look at diff? (y/n) "
			read ans
			case "$ans" in
				y|Y)
					diff -u ../../$what/reference after \
							| view -
					break
					;;
				n|N)
					break
					;;
			esac
		done
		exit 1
	else
		cd ..
		rm -rf $what
		echo "$what: OK"
	fi
fi
cd ..
rmdir --ignore-fail-on-non-empty temp || true
