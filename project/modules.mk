###############################################################################
##  JANSSON                                                                  ##
###############################################################################

.PHONY: jansson
jansson: $(JANSSON_PATH)/src/.libs/libjansson.a

$(JANSSON_PATH)/src/.libs/libjansson.a: $(JANSSON_PATH)/Makefile
	$(MAKE) -C $(JANSSON_PATH)

$(JANSSON_PATH)/Makefile: $(JANSSON_PATH)/configure
	cd $(JANSSON_PATH) && ./configure

$(JANSSON_PATH)/configure:
	cd $(JANSSON_PATH) && autoreconf -i

$(JANSSON_PATH)/Makefile: $(JANSSON_PATH)/configure

.PHONY: jansson-clean
jansson-clean:
	if [ -e '$(JANSSON_PATH)/Makefile' ]; then \
		$(MAKE) -C $(JANSSON_PATH) clean || true; \
		$(MAKE) -C $(JANSSON_PATH) distclean || true; \
	fi; \

###############################################################################
##  MODULES                                                                  ##
###############################################################################

.PHONY: modules
modules: jansson

.PHONY: modules-clean
modules-clean: jansson-clean