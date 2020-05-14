SRC:=
LIB_DIR:=.

include ../common.mk
CFLAGS+=-Wno-mismatched-tags

CONFIG_FLAGS=no-asm no-shared no-threads no-fips no-legacy no-tests enable-fuzz-afl \
		enable-tls1_3 enable-weak-ssl-ciphers enable-rc5 enable-md2 \
		enable-ssl3 enable-ssl3-method enable-nextprotoneg

ifdef PERF
	TARGET=apps/openssl
else
	TARGET=fuzz/server
endif


native:
	cd $(LIB_DIR) && \
		./config $(CONFIG_FLAGS) \
		CC=$(CC) CXX=$(CXX) CFLAGS="$(CFLAGS) $(NATIVE_FLAGS)" CXXFLAGS="$(CFLAGS) $(NATIVE_FLAGS)" LDFLAGS="$(LDFLAGS) $(NATIVE_LDFLAGS)"
	$(MAKE) run_build
	cp $(LIB_DIR)/$(TARGET) $@

nativecov:
	cd $(LIB_DIR) && \
		./config $(CONFIG_FLAGS) \
		CC=$(CCSF) CXX=$(CXXSF) CFLAGS="$(CFLAGS) $(NATIVECOV_FLAGS)" CXXFLAGS="$(CFLAGS) $(NATIVECOV_FLAGS)" LDFLAGS="$(LDFLAGS) $(NATIVECOV_LDFLAGS)"
	$(MAKE) run_build
	cp $(LIB_DIR)/$(TARGET) $@

sf:
	cd $(LIB_DIR) && \
		./config $(CONFIG_FLAGS) \
		CC=$(CCSF) CXX=$(CXXSF) CFLAGS="$(CFLAGS) $(SF_FLAGS)" CXXFLAGS="$(CFLAGS) $(SF_FLAGS)" LDFLAGS="$(LDFLAGS) $(SF_LDFLAGS)"
	$(MAKE) run_build
	cp $(LIB_DIR)/$(TARGET) $@

slh:
	cd $(LIB_DIR) && \
		./config $(CONFIG_FLAGS) \
		CC=$(CCSLH) CXX=$(CXXSLH) CFLAGS="$(CFLAGS) $(SLH_FLAGS)" CXXFLAGS="$(CFLAGS) $(SLH_FLAGS)" LDFLAGS="$(LDFLAGS) $(SLH_LDFLAGS)"
	$(MAKE) run_build
	cp $(LIB_DIR)/$(TARGET) $@

patched:
	cd $(LIB_DIR) && \
		./config $(CONFIG_FLAGS) \
		CC=$(CCSLH) CXX=$(CXXSLH) CFLAGS="$(CFLAGS) $(PATCH_FLAGS)" CXXFLAGS="$(CFLAGS) $(PATCH_FLAGS)" LDFLAGS="$(LDFLAGS) $(PATCH_LDFLAGS)"
	$(MAKE) run_build
	cp $(LIB_DIR)/$(TARGET) $@

run_build:
	cd $(LIB_DIR) && $(MAKE) clean
	cd $(LIB_DIR) && $(MAKE) -j12

clean:
	rm -f *.o $(ALL_TYPES)
