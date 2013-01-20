SUBDIRS = src

style:
	find . -name "*.[ch]" -exec perl -pi -e 's/[ \t]+$$//' {} \;
	find . -name "*.[ch]" -exec astyle --formatted --mode=c --suffix=none \
		--indent=spaces=2 --indent-switches --indent-preprocessor \
		--keep-one-line-blocks --max-instatement-indent=60 \
		--brackets=linux --pad-oper --unpad-paren --pad-header \
		--align-pointer=name {} \;

