#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# [27/08/2014]  Anna-Kaisa Pietilainen <anna-kaisa.pietilainen@inria.fr>
#		Cloned and updated from:
#	 	https://github.com/brimstone/nodejs-openwrt
#
include $(TOPDIR)/rules.mk

PKG_NAME:=node
PKG_VERSION:=v0.10.31
PKG_RELEASE:=3
PKG_SOURCE:=node-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://nodejs.org/dist/${PKG_VERSION}
PKG_MD5SUM:=1b65fe749f8e542a56a71af2b8c3a74a

GYP_DEFINES:=v8_use_mips_abi_hardfloat=false v8_can_use_fpu_instructions=false mips_arch_variant=mips32r2  

LIBS:=-I$(TOOLCHAIN_DIR)/mips-openwrt-linux-uclibc/include/c++/4.8.3/ -I$(TOOLCHAIN_DIR)/mips-openwrt-linux-uclibc/include/c++/4.8.3/mips-openwrt-linux-uclibc/

include $(INCLUDE_DIR)/uclibc++.mk
include $(INCLUDE_DIR)/package.mk

define Package/node
	DEPENDS:=+libpthread +librt +uclibcxx +libopenssl +zlib
	SECTION:=lang
	CATEGORY:=Languages
	TITLE:=Node.js is a platform built on Chrome's JavaScript runtime
	URL:=http://nodejs.org/
endef

define Package/node/description
	Node.js is a platform built on Chrome's JavaScript runtime for easily building fast, scalable network applications. Node.js uses an event-driven, non-blocking I/O model that makes it lightweight and efficient, perfect for data-intensive real-time applications that run across distributed devices.
endef

# 	git clone -b dm-mipsbe-3.14 $(GIT_SOURCE) deps/v8; \

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) link-settings.patch $(PKG_BUILD_DIR)/
	(cd $(PKG_BUILD_DIR); \
	rm -rf deps/v8; \
	cp -r /home/apietila/openwrt/v8m-rb deps/v8; \
	patch -p1 < link-settings.patch; \
	);
endef

define Build/Configure
	(cd $(PKG_BUILD_DIR); \
	export LIBS="$(LIBS)"; \
	export CFLAGS="$(TARGET_CFLAGS) $(LIBS)"; \
	export CXXFLAGS="$(TARGET_CXXFLAGS) $(LIBS)"; \
	export GYPFLAGS="$(GYPFLAGS) -Dv8_use_mips_abi_hardfloat=false -Dv8_can_use_fpu_instructions=false -Dmips_arch_variant=mips32r2"; \
	./configure --dest-cpu=mips --dest-os=linux --without-snapshot --with-mips-float-abi=soft --shared-openssl --shared-openssl-includes="$(STAGING_DIR)/usr/include" --shared-openssl-libpath="$(STAGING_DIR)/usr/lib" --shared-zlib --shared-zlib-includes="$(STAGING_DIR)/usr/include" --shared-zlib-libpath="$(STAGING_DIR)/usr/lib" --shared-v8; \
	);
endef

define Build/Compile
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) GYP_DEFINES="$(GYP_DEFINES)" CC="$(TARGET_CC)" CXX="$(TARGET_CXX)" CFLAGS="$(TARGET_CFLAGS) $(LIBS)" CXXFLAGS="$(TARGET_CXXFLAGS) $(LIBS) -nostdinc++" LDFLAGS="$(TARGET_LDFLAGS) -nodefaultlibs -luClibc++ -lc -lgcc -lgcc_s -lpthread" || touch $(PKG_BUILD_DIR)/deps/v8/build/common.gypi
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) GYP_DEFINES="$(GYP_DEFINES)" CC="$(TARGET_CC)" CXX="$(TARGET_CXX)" CFLAGS="$(TARGET_CFLAGS) $(LIBS)" CXXFLAGS="$(TARGET_CXXFLAGS) $(LIBS) -nostdinc++" LDFLAGS="$(TARGET_LDFLAGS) -nodefaultlibs -luClibc++ -lc -lgcc -lgcc_s -lpthread"
endef

define Package/node/install
	mkdir -p $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/out/Release/node $(1)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/out/Release/npm $(1)/usr/bin/
endef

$(eval $(call BuildPackage,node))
