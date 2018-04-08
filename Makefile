##############################################################
#               CMake Project Wrapper Makefile               #
##############################################################

RM := rm -rf

all: ./build/Makefile
	@ $(MAKE) -C build

./build/Makefile:
	@ mkdir -p build
	@ (cd build && cmake ..)

distclean:
	@- (cd build >/dev/null 2>&1 && cmake .. >/dev/null 2>&1)
	@- $(MAKE) --silent -C build clean || true
	@- $(RM) ./build/Makefile
	@- $(RM) ./build/src
	@- $(RM) ./build/tests
	@- $(RM) ./build/CMake*
	@- $(RM) ./build/cmake.*
	@- $(RM) ./build/Testing
	@- $(RM) ./build/*.cmake
	@- $(RM) ./build/*.tcl

ifeq ($(findstring distclean,$(MAKECMDGOALS)),)
    $(MAKECMDGOALS): ./build/Makefile
	@ $(MAKE) -C build $(MAKECMDGOALS)
endif
