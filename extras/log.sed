#!/bin/sed -rf
/ql_(log|dbg|log_pci|dbg_pci)[ \t]*\(/ {
	:a
	/\)[ \t\n]*;/ {
		s/[ \t\n]+/ /g
		s/" "//g
		s/" /"/
		/\( *(uint32_t )*level *,/d
		/".+"/!d
		/" *$/!b
	}
	N
	b a
}
d
