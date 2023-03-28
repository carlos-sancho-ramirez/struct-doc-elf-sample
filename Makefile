build/bin/elf_sample: src/*.c build/include/elf_structs.h
	mkdir -p build/bin
	cc -o $@ -Ibuild/include src/*.c

release: src/*.c build/include/elf_structs.h
	mkdir -p build/bin
	cc -O3 -o build/bin/elf_sample -Ibuild/include src/*.c
	strip --strip-unneeded build/bin/elf_sample

build/include/elf_structs.h:
	mkdir -p build/include
	echo "#ifndef _ELF_STRUCTS_H_" > $@
	echo "#define _ELF_STRUCTS_H_" >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/Header >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/HeaderX --in-types "w16=word16LittleEndian;w32=word32LittleEndian;addr=word64LittleEndian;offset=word64LittleEndian" >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/ProgramEntry --in-types "w32=word32LittleEndian;w32Just32=void;w32Just64=word32LittleEndian;addr=word64LittleEndian;offset=word64LittleEndian" >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/SectionEntry --in-types "stringOffset=word32LittleEndian;flags=word64LittleEndian;w32=word32LittleEndian;addr=word64LittleEndian;offset=word64LittleEndian" >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/SymbolEntry64 --in-types "w16=word16LittleEndian;w32=word32LittleEndian;w64=word64LittleEndian" >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/RelocationEntry64WithAddend --in-types "w64=word64LittleEndian" >> $@
	echo "" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/DynamicEntry --in-types "word=word64LittleEndian" >> $@
	echo "" >> $@
	echo "#endif // _ELF_STRUCTS_H_" >> $@

clean:
	rm -r build
