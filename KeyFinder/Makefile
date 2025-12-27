CPPSRC:=$(wildcard *.cpp)

all:
ifeq ($(BUILD_CUDA), 1)
	${CXX} -DBUILD_CUDA -o cuKeyFinder.bin ${CPPSRC} ${INCLUDE} -I${CUDA_INCLUDE} ${CXXFLAGS} ${LIBS} -L${CUDA_LIB} -Wl,--start-group -lkeyfinder -laddressutil -lcryptoutil -lsecp256k1 -lutil -llogger -lcmdparse -lCudaKeySearchDevice -lcudautil -lcudadevrt -lcudart -Wl,--end-group
	mkdir -p $(BINDIR)
	cp cuKeyFinder.bin $(BINDIR)/cuKeyFinder
endif

clean:
	rm -rf cuKeyFinder.bin
