# Auto generated file, modify if you want to add functions.

.PHONY: all
all:
	make -C src TARGET=../bin

.PHONY: clean
clean:
	rm nameserver dnstest
	make -C src clean

README: README.md
	pandoc README.md --latex-engine=xelatex -o README.pdf
