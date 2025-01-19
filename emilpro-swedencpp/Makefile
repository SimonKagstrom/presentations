all: output/presentation.pdf

output/%.png: plantuml/%.pu plantuml/objects.pu
	mkdir -p output
	plantuml -tpng $< -o `pwd`/output

presentation.tex: \
	images/elf_background.png \
	images/elf_sections.png \
	images/elf_symbols.png \
	images/elf_instructions.png \
	images/elf_relocations.png \
	images/elf_undefined_section.png \
	output/compiler_linker.png \
	output/disassembler.png \
	output/emilpro_structure.png \
	output/loader.png \


output/presentation.pdf: presentation.tex
	mkdir -p output
	cd output && pdflatex ../presentation.tex

view: output/presentation.pdf
	pdfpc --notes=left $<
