ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = switch/p4src switch/switchapi

prog_CFLAGS = $(AM_CFLAGS)
DBG_CFLAGS = -g -O0

PFX ?=

p4_plugin_files = \
src/netdev-p4-sim.c \
src/ofproto-p4-sim-provider.c \
src/p4-switch.c \
src/p4-sim-plugins.c

noinst_LTLIBRARIES = libovs_p4_sim_plugin_interface.la
libovs_p4_sim_plugin_interface_la_SOURCES = $(p4_plugin_files)
libovs_p4_sim_plugin_interface_la_CFLAGS = -I $(srcdir)/include
libovs_p4_sim_plugin_interface_la_CFLAGS += $(includedir)
libovs_p4_sim_plugin_interface_la_CFLAGS += $(LIBOVSCOMMON_CFLAGS)
libovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/switchapi/include
libovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/switchapi/third-party/tommyds/include
libovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/p4src/includes
libovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/p4src/bmv2_p4_pd
libovs_p4_sim_plugin_interface_la_CFLAGS += $(P4C_LIBPDFIXED_CFLAGS)

libovs_p4_sim_plugin_interface_la_CFLAGS += -std=gnu99 -D BMV2
libovs_p4_sim_plugin_interface_la_CFLAGS += $(DBG_CFLAGS)

SWITCHAPI_DIR = $(srcdir)/switch/switchapi
SWITCHAPI_LIB := $(SWITCHAPI_DIR)/libswitchapi.la

SWITCHP4_DIR = $(srcdir)/switch/p4src
SWITCHP4_PD_LIB := $(SWITCHP4_DIR)/libbmv2pd.la

BUILT_SOURCES = $(datadir)/switch_bmv2.json

$(SWITCHP4_PD_LIB):
	@$(MAKE) -C $(SWITCHP4_DIR) PFX=$(PFX)

$(BUILT_SOURCES) : $(SWITCHP4_PD_LIB)
	@$(MAKE) -C $(SWITCHAPI_DIR) PFX=$(PFX)

# need to find a way to link all libs together into a single .so
# catch (for not using LIBADD) is the dependency
lib_LTLIBRARIES = libovs_p4_sim_plugin.la

libovs_p4_sim_plugin_la_SOURCES =
libovs_p4_sim_plugin_la_CFLAGS = $(THRIFT_CFLAGS) $(P4C_LIBPDFIXED_CFLAGS) $(BMV2_LIBTHRIFT_CFLAGS)
libovs_p4_sim_plugin_la_LIBADD = $(noinst_LTLIBRARIES) $(SWITCHAPI_LIB) $(SWITCHP4_PD_LIB) \
    $(BMV2_LIBTHRIFT_LIBS) $(LIBOVSCOMMON_LIBS) $(THRIFT_LIBS) $(P4C_LIBPDFIXED_LIBS)

# Remove libs that are not packaged, yocto complains otherwise
install-exec-hook:
	install -d $(DESTDIR)/$(libdir)/openvswitch/plugins
	mv $(DESTDIR)/$(libdir)/libovs_p4_sim_plugin.so.0.0.0 $(DESTDIR)/$(libdir)/openvswitch/plugins/libovs_p4_sim_plugin.so
	rm -f $(DESTDIR)/$(libdir)/libovs_p4_sim_plugin.so.*

CLEANFILES = $(lib_LTLIBRARIES) $(BUILT_SOURCES)
.PHONY: $(SWITCHP4_PD_LIB)
