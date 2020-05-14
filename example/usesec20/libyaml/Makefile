SRC:=
LIB_DIR:=.

include ../common.mk

ifdef PERF
	TARGET=run-loader
else
	TARGET=fuzzer
endif

native:
	cd $(LIB_DIR) && \
		CC=$(CC) CXX=$(CXX) CFLAGS="$(CFLAGS) $(NATIVE_FLAGS)" CXXFLAGS="$(CFLAGS) $(NATIVE_FLAGS)" LDFLAGS="$(LDFLAGS) $(NATIVE_LDFLAGS)" \
		./configure --disable-shared
	$(MAKE) run_build
	cp $(LIB_DIR)/tests/$(TARGET) $@

nativecov:
	cd $(LIB_DIR) && \
		CC=$(CCSF) CXX=$(CXXSF) CFLAGS="$(CFLAGS) $(NATIVECOV_FLAGS)" CXXFLAGS="$(CFLAGS) $(NATIVECOV_FLAGS)" LDFLAGS="$(LDFLAGS) $(NATIVECOV_LDFLAGS)" \
		./configure --disable-shared
	$(MAKE) run_build
	cp $(LIB_DIR)/tests/$(TARGET) $@

sf:
	cd $(LIB_DIR) && \
		CC=$(CCSF) CXX=$(CXXSF) CFLAGS="$(CFLAGS) $(SF_FLAGS)" CXXFLAGS="$(CFLAGS) $(SF_FLAGS)" LDFLAGS="$(LDFLAGS) $(SF_LDFLAGS)" \
		./configure --disable-shared
	$(MAKE) run_build
	cp $(LIB_DIR)/tests/$(TARGET) $@

slh:
	cd $(LIB_DIR) && \
		CC=$(CCSLH) CXX=$(CXXSLH) CFLAGS="$(CFLAGS) $(SLH_FLAGS)" CXXFLAGS="$(CFLAGS) $(SLH_FLAGS)" LDFLAGS="$(LDFLAGS) $(SLH_LDFLAGS)" \
		./configure --disable-shared
	$(MAKE) run_build
	cp $(LIB_DIR)/tests/$(TARGET) $@

patched:
	cd $(LIB_DIR) && \
		CC=$(CCSLH) CXX=$(CXXSLH) CFLAGS="$(CFLAGS) $(PATCH_FLAGS)" CXXFLAGS="$(CFLAGS) $(PATCH_FLAGS)" LDFLAGS="$(LDFLAGS) $(PATCH_LDFLAGS)" \
		./configure --disable-shared
	$(MAKE) run_build
	cp $(LIB_DIR)/tests/$(TARGET) $@

run_build:
	$(MAKE) -C $(LIB_DIR) clean
	$(MAKE) -j8 -C $(LIB_DIR)
	$(MAKE) -j8 -C $(LIB_DIR)/tests $(TARGET)

clean:
	rm -f *.o $(ALL_TYPES)
