all:
	find ${PFX} -name p4c-bmv2
	cat ${PFX}/usr/bin/p4c-bmv2
	ls -l `head -1 "${PFX}/usr/bin/p4c-bmv2" | cut -c3-`
	ls -l `readlink -m $$(head -1 "${PFX}/usr/bin/p4c-bmv2" | cut -c3-)`
	file `readlink -m $$(head -1 "${PFX}/usr/bin/p4c-bmv2" | cut -c3-)`
	objdump -x `readlink -m $$(head -1 "${PFX}/usr/bin/p4c-bmv2" | cut -c3-)`
	echo PATH=$PATH
	exit 42
