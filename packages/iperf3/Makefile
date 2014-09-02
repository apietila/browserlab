#
# Copyright (C) 2007-2010 OpenWrt.org
# Copyright (C) 2014 Anna-Kaisa Pietilainen <anna-kaisa.pietilainen@inria.fr>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=iperf3
PKG_VERSION:=3.0.7
PKG_RELEASE:=1

PKG_SOURCE_URL:=http://downloads.es.net/pub/iperf/
PKG_SOURCE:=iperf-$(PKG_VERSION).tar.gz
PKG_MD5SUM:=71b0df095b7680a9fa36725ee061f31e

PKG_BUILD_DIR:=$(BUILD_DIR)/iperf-$(PKG_VERSION)

PKG_FIXUP:=autoreconf

#EXTRA_LDFLAGS:=-nodefaultlibs -luClibc++
#EXTRA_CFLAGS:=-I$(STAGING_DIR)/usr/include/uClibc++

include $(INCLUDE_DIR)/uclibc++.mk
include $(INCLUDE_DIR)/package.mk

define Package/iperf3
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Iperf3
	DEPENDS:=+libpthread +uclibcxx
	URL:=http://software.es.net/iperf/
endef

define Package/iperf3/description
	UDP and TCP bandwidth measurement tool.
endef

define Build/Configure
	$(call Build/Configure/Default,--disable-shared --disable-static)
endef

define Package/iperf3/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/iperf3 $(1)/usr/bin/iperf3
endef

$(eval $(call BuildPackage,iperf3))
