all: output/presentation.pdf

output/presentation.pdf: presentation.tex
	mkdir -p output
	cd output && pdflatex ../presentation.tex

view: output/presentation.pdf
	xpdf -fullscreen $<
