build/bin/elf_sample: src/*.c build/include/elf_structs.h
	mkdir -p build/bin
	cc -o $@ -Ibuild/include src/*.c

build/include/elf_structs.h:
	mkdir -p build/include
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/Header > $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/HeaderX --in-types "w16=word16LittleEndian;w32=word32LittleEndian;addr=word64LittleEndian;offset=word64LittleEndian" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/ProgramEntry --in-types "w32=word32LittleEndian;w32Just32=void;w32Just64=word32LittleEndian;addr=word64LittleEndian;offset=word64LittleEndian" >> $@
	../struct-doc-instancer/build/instancer --in-template ../struct-doc/elf/SectionEntry --in-types "stringOffset=word32LittleEndian;flags=word64LittleEndian;w32=word32LittleEndian;addr=word64LittleEndian;offset=word64LittleEndian" >> $@

clean:
	rm -r build
