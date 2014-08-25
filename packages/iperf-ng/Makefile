#
# Copyright (C) 2007-2010 OpenWrt.org (original iperf)
# Copyright (C) 2014 Inria Paris-Roquencourt (iperf-ng)
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=iperf-ng
PKG_VERSION:=2.0.6

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/apietila/iperf-ng.git
PKG_SOURCE:=$(PKG_NAME).tar.gz
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=$(PKG_NAME)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/uclibc++.mk
include $(INCLUDE_DIR)/package.mk

define Package/iperf-ng/Default
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:= $(CXX_DEPENDS)
  TITLE:=Internet Protocol bandwidth measuring tool
  URL:=https://github.com/apietila/iperf-ng
endef

define Package/iperf-ng/Default/description
 Iperf is a modern alternative for measuring TCP and UDP bandwidth
 performance, allowing the tuning of various parameters and
 characteristics. Iperf-NG adds NAT traversal and JSON output options.
endef

define Package/iperf-ng
$(call Package/iperf-ng/Default)
  TITLE+= (with single thread support)
  VARIANT:=single
endef

define Package/iperf-ng/description
$(call Package/iperf-ng/Default/description)
 This package is built with single thread support.
endef

define Package/iperf-ng-mt
$(call Package/iperf-ng/Default)
  DEPENDS+= +libpthread
  TITLE+= (with multithread support)
  VARIANT:=mt
endef

define Package/iperf-ng-mt/description
$(call Package/iperf-ng/Default/description)
 This package is built with multithread support.
endef

CONFIGURE_ARGS += --disable-multicast
CONFIGURE_VARS += ac_cv_func_malloc_0_nonnull=yes

ifeq ($(BUILD_VARIANT),single)
  CONFIGURE_ARGS += --disable-threads
else
  CONFIGURE_ARGS += --enable-threads=posix
  CONFIGURE_VARS += ac_cv_func_pthread_cancel=no
endif

CONFIGURE_VARS += CXXFLAGS="$$$$CXXFLAGS -fno-rtti"

ifeq ($(BUILD_VARIANT),mt)
  CONFIGURE_VARS += LIBS="-lpthread"
endif

define Package/iperf-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/iperf $(1)/usr/bin/iperf-ng
endef
Package/iperf-ng-mt/install = $(Package/iperf-ng/install)

$(eval $(call BuildPackage,iperf-ng))
$(eval $(call BuildPackage,iperf-ng-mt))
