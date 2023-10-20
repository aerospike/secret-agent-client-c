###############################################################################
##  BUILD ENVIRONMENT                                                        ##
###############################################################################

NAME = $(shell basename $(CURDIR))
OS = $(shell uname)
ARCH = $(shell uname -m)

PROJECT = project
SOURCE  = src
TARGET  = target

###############################################################################
##  SUBMODULES                                                               ##
###############################################################################

JANSSON_PATH = ./modules/jansson

JANSSON_SOURCE = $(JANSSON_PATH)/src
JANSSON_INCL = $(JANSSON_PATH)/src

JANSSON_SOURCE_NAMES = $(basename $(notdir $(wildcard $(JANSSON_SOURCE)/*.c)))
JANSSON_OBJECTS = $(JANSSON_SOURCE_NAMES:%=$(JANSSON_SOURCE)/%.o)

MODULE_INCL = $(JANSSON_INCL)
MODULE_OBJECTS = $(JANSSON_OBJECTS)

###############################################################################
##  SOURCE PATHS                                                             ##
###############################################################################

SOURCE_PATH = $(SOURCE)
SOURCE_MAIN = $(SOURCE_PATH)/main
SOURCE_INCL = $(SOURCE_PATH)/include
SOURCE_TEST = $(SOURCE)/test

LIB_PATH = 
INC_PATH = -I$(SOURCE_INCL)
INC_PATH += -I$(MODULE_INCL)

###############################################################################
##  TARGET PATHS                                                             ##
###############################################################################

PLATFORM = $(OS)-$(ARCH)
TARGET_BASE = $(TARGET)/$(PLATFORM)
TARGET_LIB  = $(TARGET_BASE)/lib
TARGET_OBJ  = $(TARGET_BASE)/obj
TARGET_INCL = $(TARGET_BASE)/include
TARGET_TEST = $(SOURCE_TEST)/tests

###############################################################################
##  SOURCE                                                                  ##
###############################################################################

SOURCES = 
SOURCES += $(wildcard $(SOURCE_MAIN)/*.c)

SOURCE_NAMES = 
SOURCE_NAMES += $(basename $(notdir $(wildcard $(SOURCE_MAIN)/*.c)))

###############################################################################
##  HEADERS                                                                  ##
###############################################################################

HEADERS =
HEADERS += $(wildcard $(SOURCE_INCL)/*.h)

HEADER_NAMES =
HEADER_NAMES += $(basename $(notdir $(wildcard $(SOURCE_INCL)/*.h)))

###############################################################################
##  SETTINGS                                                                 ##
###############################################################################

LIBRARIES := 
LIBRARIES += -lssl
LIBRARIES += -lcrypto

ifeq ($(OS),Darwin)
  DYNAMIC_SUFFIX=dylib
  DYNAMIC_FLAG=-dynamiclib
else
  DYNAMIC_SUFFIX=so
  DYNAMIC_FLAG=-shared
endif

M1_HOME_BREW =
ifeq ($(OS),Darwin)
	ifneq ($(wildcard /opt/homebrew),)
		M1_HOME_BREW = true
	endif
endif

ifdef M1_HOME_BREW
	INC_PATH += -I/opt/homebrew/include
	LIB_PATH += -L/opt/homebrew/lib
endif

CFLAGS :=
CFLAGS += -fPIC
CFLAGS += -g
CFLAGS += -o2

ARFLAGS :=
ARFLAGS += rvs

###############################################################################
##  TARGETS                                                                  ##
###############################################################################
OBJECTS = $(SOURCE_NAMES:%=$(TARGET_OBJ)/%.o)
TARGET_HEADERS = $(HEADER_NAMES:%=$(TARGET_INCL)/%.h)

CLIENT_SHARED = $(TARGET_LIB)/libsecret-agent-client-c.$(DYNAMIC_SUFFIX)
CLIENT_STATIC = $(TARGET_LIB)/libsecret-agent-client-c.a

all: modules $(TARGET) $(OBJECTS) $(CLIENT_SHARED) $(CLIENT_STATIC) $(TARGET_HEADERS)

$(TARGET):
	mkdir $(TARGET)

$(TARGET_OBJ)/%.o: $(SOURCE_MAIN)/%.c | $(TARGET) 
	@if [ ! -d `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(strip $(CC) \
		$(INC_PATH) \
		$(CFLAGS) \
		-o $@ \
		-c $(filter %.c, $<)  \
	)

$(CLIENT_SHARED): $(MODULE_OBJECTS) $(OBJECTS) | $(TARGET)
	@if [ ! -d `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(strip $(CC) $(DYNAMIC_FLAG) \
		$(INC_PATH) \
		$(LIB_PATH) \
		$(LIBRARIES) \
		-o $@ \
		$(filter %.o, $^) \
		$(LD_FLAGS) \
	)

$(CLIENT_STATIC): $(MODULE_OBJECTS) $(OBJECTS) | $(TARGET) 
	@if [ ! -d `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(strip $(AR) \
		$(ARFLAGS) \
		$@ \
		$(filter %.o, $^) \
	)

$(TARGET_INCL)/%.h: $(SOURCE_INCL)/%.h | $(TARGET)
	@if [ ! -d `dirname $@` ]; then mkdir -p `dirname $@`; fi
	cp -p $^ $@

.PHONY: clean
clean: modules-clean
	rm -rf $(TARGET)
	rm -f $(TARGET_TEST)

.PHONY: test
test: $(TARGET_TEST)
	./src/test/tests

$(TARGET_TEST): all
	#linux $(CC) $(TARGET_TEST).c -g -o0 -I./src/include -L./$(TARGET_LIB) -lsecret-agent-client-c -lssl -lcrypto -o $@
	#linux static $(CC) $(TARGET_TEST).c -g -o0 -I./src/include -I/opt/homebrew/include -L./$(TARGET_LIB) -l:libsecret-agent-client-c.a -lssl -lcrypto -o $@

	#mac $(CC) $(TARGET_TEST).c -g -o0 -I./src/include -I/opt/homebrew/include -L./target/Darwin-arm64/lib/ -lsecret-agent-client-c -o $@
	#mac static $(CC) $(TARGET_TEST).c -g -o0 -I./src/include -I./modules/jansson/src -I/opt/homebrew/include ./target/Darwin-arm64/lib/libsecret-agent-client-c.a -L/opt/homebrew/lib -lssl -lcrypto -o $@

	$(CC) $(TARGET_TEST).c -g -o0 -I./src/include -I/opt/homebrew/include -L./target/Darwin-arm64/lib/ -lsecret-agent-client-c -o

###############################################################################
include project/modules.mk