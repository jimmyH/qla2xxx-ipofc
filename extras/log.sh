#!/bin/bash
log() {
	sed -rf <(cat - <<-SED
		/ql_(log|dbg|log_pci|dbg_pci)[ \t]*\(/ {
			:a
			/\)[ \t\n]*;/ {
				s/[ \t\n]+/ /g
				s/\" \"//g
				s/\" /\"/
				/\( *(uint32_t )*level *,/d
				/\".+\"/!d
				/\" *$/!b
			}
			N
			b a
		}
		d
	SED
	) $@
}

help() {
	cat <<-END
		$0	extract log/dbg messages from driver source

		$0  sort-option  [ tabulate-option ]

		sort-option is required, must be one of:
		--cat	sort by message category
		--str	sort by message string
		--id	sort by message id

		tabulate-option is optional:
		--tab	tabulate output (strip away C syntax)
	END
	exit
}

tab() {
	sed -r 's/^(.*?) *\( *(.*?) *, *(.*?) *, *(0x[0-9A-Fa-f]{1,}) *, *(".*") *[,)] *.*$/\2\t\4\t\5/'
}

ctg() {
	$0 --cat --tab | awk -F '\t' '{ print $1 }' | sort -u
	exit
}

case $1 in
	"--cat"	) sort="-t, -k1,1" ;;
	"--str"	) sort="-t, -k4,4" ;;
	"--id"	) sort="-t, -k3,3 -g" ;;
	"cat"   ) ctg ;;
	*	) help ;;
esac
case $2 in
	"--tab"	) log *.[ch] | sort $sort | tab ;;
	""	) log *.[ch] | sort $sort ;;
	*	) help ;;
esac
