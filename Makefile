# Auto generated file, modify if you want to add functions.

.PHONY: all
all: init clean
	make -C src TARGET=../bin
	cp bin/nameserver bin/dnstest .

.PHONY: init
init:
	-mkdir bin

.PHONY: clean
clean:
	-rm nameserver dnstest
	make -C src clean

README: README.md
	pandoc README.md --latex-engine=xelatex -o README.pdf
