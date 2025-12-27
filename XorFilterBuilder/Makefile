NAME=xorfilterbuilder
SRC=$(wildcard *.cpp)

all:    ${SRC}
	mkdir -p ${BINDIR}
	${CXX} -o ${BINDIR}/xorfilterbuilder ${SRC} ${INCLUDE} ${CXXFLAGS} ${LIBS} -Wl,--start-group -laddressutil -lsecp256k1 -lcryptoutil -lutil -llogger -lcmdparse -Wl,--end-group

clean:
	rm -f ${BINDIR}/xorfilterbuilder