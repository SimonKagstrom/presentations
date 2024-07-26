all: output/presentation.pdf

output/%.png: plantuml/%.pu plantuml/objects.pu
	mkdir -p output
	plantuml -tpng $< -o `pwd`/output

presentation.tex: \
	output/compiler_linker.png \
	output/loader.png \


output/presentation.pdf: presentation.tex
	mkdir -p output
	cd output && pdflatex ../presentation.tex

view: output/presentation.pdf
	pdfpc --notes=left $<
