#!/bin/bash
log=${0/%.sh/.sed}

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
	sed -r 's/^(.*?) *\( *(.*?) *, *(.*?) *, *(0x[0-9A-Fa-f]{1,4}) *, *(".*") *[,)] *.*$/\2\t\4\t\5/'
}

case $1 in
	"--cat"	) sort="sort -t, -k1,1" ;;
	"--str"	) sort="sort -t, -k4,4" ;;
	"--id"	) sort="sort -t, -k3,3 -g" ;;
	*	) help ;;
esac
case $2 in
	"--tab"	) $log *.[ch] | $sort | tab ;;
	""	) $log *.[ch] | $sort ;;
	*	) help ;;
esac
