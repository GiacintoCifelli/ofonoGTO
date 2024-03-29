
AM_MAKEFLAGS = --no-print-directory

noinst_LTLIBRARIES =

if EXTERNAL_ELL
ell_cflags = @ELL_CFLAGS@
ell_ldadd = @ELL_LIBS@
ell_dependencies =
ell_built_sources =
else
ell_cflags =
ell_ldadd = ell/libell-internal.la
ell_dependencies = $(ell_ldadd)
ell_built_sources = ell/internal ell/ell.h

noinst_LTLIBRARIES += ell/libell-internal.la

ell_headers = ell/util.h \
			ell/test.h \
			ell/strv.h \
			ell/utf8.h \
			ell/queue.h \
			ell/timeout.h \
			ell/main.h \
			ell/idle.h \
			ell/signal.h \
			ell/io.h \
			ell/log.h \
			ell/checksum.h \
			ell/random.h \
			ell/uuid.h \
			ell/file.h \
			ell/uintset.h \
			ell/string.h \
			ell/gpio.h

ell_sources = ell/private.h \
			ell/missing.h \
			ell/main-private.h \
			ell/util.c \
			ell/test.c \
			ell/strv.c \
			ell/utf8.c \
			ell/queue.c \
			ell/timeout.c \
			ell/main.c \
			ell/idle.c \
			ell/signal.c \
			ell/io.c \
			ell/log.c \
			ell/checksum.c \
			ell/random.c \
			ell/uuid.c \
			ell/file.c \
			ell/uintset.c \
			ell/string.c \
			ell/gpio.c

ell_libell_internal_la_SOURCES = $(ell_headers) $(ell_sources)
endif

pkginclude_HEADERS = include/log.h include/plugin.h include/history.h \
			include/dbus.h include/modem.h include/types.h \
			include/call-barring.h include/call-forwarding.h \
			include/call-meter.h include/call-settings.h \
			include/phonebook.h include/ussd.h \
			include/sms.h include/sim.h include/message-waiting.h \
			include/netreg.h include/voicecall.h include/devinfo.h \
			include/cbs.h include/call-volume.h \
			include/gprs.h include/gprs-context.h \
			include/radio-settings.h include/stk.h \
			include/audio-settings.h include/nettime.h \
			include/ctm.h include/cdma-voicecall.h \
			include/cdma-sms.h include/sim-auth.h \
			include/gprs-provision.h include/emulator.h \
			include/location-reporting.h \
			include/cdma-connman.h include/gnss.h \
			include/private-network.h include/cdma-netreg.h \
			include/cdma-provision.h include/handsfree.h \
			include/handsfree-audio.h include/siri.h \
			include/netmon.h include/lte.h include/ims.h \
			include/storage.h include/gemalto.h

nodist_pkginclude_HEADERS = include/version.h

local_headers = $(foreach file,$(pkginclude_HEADERS) \
				$(nodist_pkginclude_HEADERS), \
					include/ofono/$(notdir $(file)))

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ofono.pc


if DATAFILES
dbusconfdir = @DBUS_CONFDIR@

dist_dbusconf_DATA = src/ofono.conf

if SYSTEMD
systemdunitdir = @SYSTEMD_UNITDIR@

systemdunit_DATA = src/ofono.service
endif

confdir = $(sysconfdir)/ofono

dist_conf_DATA =

statedir = $(localstatedir)/lib/ofono

state_DATA =
endif

builtin_modules =
builtin_sources =
builtin_libadd =
builtin_cflags =

noinst_LTLIBRARIES += gdbus/libgdbus-internal.la

gdbus_libgdbus_internal_la_SOURCES = gdbus/gdbus.h \
				gdbus/mainloop.c gdbus/watch.c \
				gdbus/object.c gdbus/client.c gdbus/polkit.c

gatchat_sources = gatchat/gatchat.h gatchat/gatchat.c \
				gatchat/gatresult.h gatchat/gatresult.c \
				gatchat/gatsyntax.h gatchat/gatsyntax.c \
				gatchat/ringbuffer.h gatchat/ringbuffer.c \
				gatchat/gatio.h	gatchat/gatio.c \
				gatchat/crc-ccitt.h gatchat/crc-ccitt.c \
				gatchat/gatmux.h gatchat/gatmux.c \
				gatchat/gsm0710.h gatchat/gsm0710.c \
				gatchat/gattty.h gatchat/gattty.c \
				gatchat/gatutil.h gatchat/gatutil.c \
				gatchat/gat.h \
				gatchat/gatserver.h gatchat/gatserver.c \
				gatchat/gatrawip.h gatchat/gatrawip.c \
				gatchat/gathdlc.c gatchat/gathdlc.h \
				gatchat/gatppp.c gatchat/gatppp.h \
				gatchat/ppp.h gatchat/ppp_cp.h \
				gatchat/ppp_cp.c gatchat/ppp_lcp.c \
				gatchat/ppp_auth.c gatchat/ppp_net.c \
				gatchat/ppp_ipcp.c gatchat/ppp_ipv6cp.c

gisi_sources = gisi/client.c gisi/client.h gisi/common.h \
				gisi/iter.c gisi/iter.h \
				gisi/message.c gisi/message.h \
				gisi/modem.c gisi/modem.h \
				gisi/netlink.c gisi/netlink.h \
				gisi/pep.c gisi/pep.h \
				gisi/phonet.h \
				gisi/pipe.c gisi/pipe.h \
				gisi/server.c gisi/server.h \
				gisi/socket.c gisi/socket.h

gril_sources = gril/gril.h gril/gril.c \
				gril/grilio.h gril/grilio.c \
				gril/grilutil.h gril/grilutil.c \
				gril/gfunc.h gril/gril.h \
				gril/parcel.c gril/parcel.h \
				gril/ril_constants.h

btio_sources = btio/btio.h btio/btio.c

if UDEV
builtin_cflags += @UDEV_CFLAGS@
builtin_libadd += @UDEV_LIBS@

builtin_modules += udevng
builtin_sources += plugins/udevng.c
endif

if RILMODEM
builtin_sources += $(gril_sources)

builtin_modules += rildev
builtin_sources += plugins/rildev.c

builtin_modules += ril
builtin_sources += plugins/ril.c plugins/ril.h

builtin_modules += infineon
builtin_sources += plugins/infineon.c

builtin_modules += ril_intel
builtin_sources += plugins/ril_intel.c

builtin_modules += rilmodem
builtin_sources += drivers/rilmodem/rilmodem.h \
			drivers/rilmodem/vendor.h \
			drivers/rilmodem/rilmodem.c \
			drivers/rilmodem/devinfo.c \
			drivers/rilmodem/network-registration.c \
			drivers/rilmodem/voicecall.c \
			drivers/rilmodem/voicecall.h \
			drivers/rilmodem/call-volume.c \
			drivers/rilmodem/gprs.c \
			drivers/rilmodem/gprs-context.c \
			drivers/rilmodem/sim.c \
			drivers/rilmodem/sms.c \
			drivers/rilmodem/rilutil.c \
			drivers/rilmodem/rilutil.h \
			drivers/rilmodem/ussd.c \
			drivers/rilmodem/call-settings.c \
			drivers/rilmodem/call-forwarding.c \
			drivers/rilmodem/radio-settings.c \
			drivers/rilmodem/call-barring.c \
			drivers/rilmodem/netmon.c \
			drivers/rilmodem/stk.c \
			drivers/rilmodem/cbs.c \
			drivers/infineonmodem/infineon_constants.h \
			drivers/rilmodem/lte.c
endif

if ISIMODEM
builtin_modules += isimodem
builtin_sources += $(gisi_sources) \
			drivers/isimodem/isimodem.h \
			drivers/isimodem/isimodem.c \
			drivers/isimodem/mtc.h \
			drivers/isimodem/debug.h \
			drivers/isimodem/isiutil.h \
			drivers/isimodem/debug.c \
			drivers/isimodem/phonebook.c \
			drivers/isimodem/devinfo.c \
			drivers/isimodem/info.h \
			drivers/isimodem/network-registration.c \
			drivers/isimodem/network.h \
			drivers/isimodem/infoserver.h \
			drivers/isimodem/infoserver.c \
			drivers/isimodem/voicecall.c \
			drivers/isimodem/call.h \
			drivers/isimodem/sms.c \
			drivers/isimodem/sms.h \
			drivers/isimodem/cbs.c \
			drivers/isimodem/sim.c \
			drivers/isimodem/sim.h \
			drivers/isimodem/ussd.c \
			drivers/isimodem/call-forwarding.c \
			drivers/isimodem/call-settings.c \
			drivers/isimodem/call-barring.c \
			drivers/isimodem/call-meter.c \
			drivers/isimodem/ss.h \
			drivers/isimodem/radio-settings.c \
			drivers/isimodem/gss.h \
			drivers/isimodem/gprs.c \
			drivers/isimodem/gprs-context.c \
			drivers/isimodem/gpds.h \
			drivers/isimodem/audio-settings.c \
			drivers/isimodem/uicc.h \
			drivers/isimodem/uicc.c \
			drivers/isimodem/uicc-util.h \
			drivers/isimodem/uicc-util.c

builtin_modules += isiusb
builtin_sources += plugins/isiusb.c

builtin_modules += n900
builtin_sources += plugins/n900.c plugins/nokia-gpio.h plugins/nokia-gpio.c

builtin_modules += u8500
builtin_sources += plugins/u8500.c
endif

if QMIMODEM
qmi_sources = drivers/qmimodem/qmi.h drivers/qmimodem/qmi.c \
					drivers/qmimodem/ctl.h \
					drivers/qmimodem/dms.h \
					drivers/qmimodem/nas.h \
					drivers/qmimodem/nas.c \
					drivers/qmimodem/uim.h \
					drivers/qmimodem/wms.h \
					drivers/qmimodem/wds.h \
					drivers/qmimodem/pds.h \
					drivers/qmimodem/common.h \
					drivers/qmimodem/wda.h \
					drivers/qmimodem/voice.h

builtin_modules += qmimodem
builtin_sources += $(qmi_sources) \
			drivers/qmimodem/util.h \
			drivers/qmimodem/qmimodem.h \
			drivers/qmimodem/qmimodem.c \
			drivers/qmimodem/devinfo.c \
			drivers/qmimodem/voicecall.c \
			drivers/qmimodem/network-registration.c \
			drivers/qmimodem/sim-legacy.c \
			drivers/qmimodem/sim.c \
			drivers/qmimodem/sms.c \
			drivers/qmimodem/ussd.c \
			drivers/qmimodem/gprs.c \
			drivers/qmimodem/gprs-context.c \
			drivers/qmimodem/lte.c \
			drivers/qmimodem/radio-settings.c \
			drivers/qmimodem/location-reporting.c \
			drivers/qmimodem/netmon.c

builtin_modules += gobi
builtin_sources += plugins/gobi.c
endif

if MBIMMODEM
mbim_sources =	drivers/mbimmodem/mbim.h \
		drivers/mbimmodem/mbim.c \
		drivers/mbimmodem/mbim-private.h \
		drivers/mbimmodem/mbim-desc.h \
		drivers/mbimmodem/mbim-desc.c \
		drivers/mbimmodem/mbim-message.h \
		drivers/mbimmodem/mbim-message.c

builtin_modules += mbimmodem
builtin_sources += $(mbim_sources) \
			drivers/mbimmodem/util.h \
			drivers/mbimmodem/util.c \
			drivers/mbimmodem/mbimmodem.h \
			drivers/mbimmodem/mbimmodem.c \
			drivers/mbimmodem/devinfo.c \
			drivers/mbimmodem/sim.c \
			drivers/mbimmodem/network-registration.c \
			drivers/mbimmodem/sms.c \
			drivers/mbimmodem/gprs.c \
			drivers/mbimmodem/gprs-context.c

builtin_modules += mbim
builtin_sources += plugins/mbim.c
endif

if ATMODEM
builtin_modules += atmodem
builtin_sources += 	drivers/atmodem/atmodem.h \
			drivers/atmodem/atmodem.c \
			drivers/atmodem/call-settings.c \
			drivers/atmodem/sms.c \
			drivers/atmodem/cbs.c \
			drivers/atmodem/call-forwarding.c \
			drivers/atmodem/call-meter.c \
			drivers/atmodem/network-registration.c \
			drivers/atmodem/sim.c \
			drivers/atmodem/stk.c \
			drivers/atmodem/stk.h \
			drivers/atmodem/ussd.c \
			drivers/atmodem/voicecall.c \
			drivers/atmodem/call-barring.c \
			drivers/atmodem/phonebook.c \
			drivers/atmodem/devinfo.c \
			drivers/atmodem/call-volume.c \
			drivers/atmodem/vendor.h \
			drivers/atmodem/atutil.h \
			drivers/atmodem/atutil.c \
			drivers/atmodem/gprs.c \
			drivers/atmodem/gprs-context.c \
			drivers/atmodem/gnss.c \
			drivers/atmodem/lte.c

builtin_modules += nwmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/nwmodem/nwmodem.h \
			drivers/nwmodem/nwmodem.c \
			drivers/nwmodem/radio-settings.c

builtin_modules += swmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/swmodem/swmodem.h \
			drivers/swmodem/swmodem.c \
			drivers/swmodem/gprs-context.c

builtin_modules += ztemodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/ztemodem/ztemodem.h \
			drivers/ztemodem/ztemodem.c \
			drivers/ztemodem/radio-settings.c

builtin_modules += iceramodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/iceramodem/iceramodem.h \
			drivers/iceramodem/iceramodem.c \
			drivers/iceramodem/gprs-context.c \
			drivers/iceramodem/radio-settings.c

builtin_modules += huaweimodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/huaweimodem/huaweimodem.h \
			drivers/huaweimodem/huaweimodem.c \
			drivers/huaweimodem/ussd.c \
			drivers/huaweimodem/voicecall.c \
			drivers/huaweimodem/audio-settings.c \
			drivers/huaweimodem/gprs-context.c \
			drivers/huaweimodem/radio-settings.c \
			drivers/huaweimodem/cdma-netreg.c

builtin_modules += calypsomodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/calypsomodem/calypsomodem.h \
			drivers/calypsomodem/calypsomodem.c \
			drivers/calypsomodem/voicecall.c \
			drivers/calypsomodem/stk.c

builtin_modules += mbmmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/mbmmodem/mbmmodem.h \
			drivers/mbmmodem/mbmmodem.c \
			drivers/mbmmodem/gprs-context.c \
			drivers/mbmmodem/stk.c \
			drivers/mbmmodem/location-reporting.c

builtin_modules += telitmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/telitmodem/telitmodem.h \
			drivers/telitmodem/telitmodem.c \
			drivers/telitmodem/location-reporting.c \
			drivers/telitmodem/gprs-context-ncm.c

builtin_modules += hsomodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/hsomodem/hsomodem.h \
			drivers/hsomodem/hsomodem.c \
			drivers/hsomodem/gprs-context.c \
			drivers/hsomodem/radio-settings.c

builtin_modules += ifxmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/ifxmodem/ifxmodem.h \
			drivers/ifxmodem/ifxmodem.c \
			drivers/ifxmodem/voicecall.c \
			drivers/ifxmodem/audio-settings.c \
			drivers/ifxmodem/radio-settings.c \
			drivers/ifxmodem/gprs-context.c \
			drivers/ifxmodem/stk.c \
			drivers/ifxmodem/ctm.c

builtin_modules += stemodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/stemodem/stemodem.h \
			drivers/stemodem/stemodem.c \
			drivers/stemodem/voicecall.c \
			drivers/stemodem/radio-settings.c \
			drivers/stemodem/caif_rtnl.c \
			drivers/stemodem/caif_rtnl.h \
			drivers/stemodem/gprs-context.c \
			drivers/stemodem/caif_socket.h \
			drivers/stemodem/if_caif.h

builtin_modules += dunmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/dunmodem/dunmodem.h \
			drivers/dunmodem/dunmodem.c \
			drivers/dunmodem/network-registration.c \
			drivers/dunmodem/gprs.c

builtin_modules += hfpmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/hfpmodem/hfpmodem.h \
			drivers/hfpmodem/hfpmodem.c \
			drivers/hfpmodem/slc.h \
			drivers/hfpmodem/slc.c \
			drivers/hfpmodem/voicecall.c \
			drivers/hfpmodem/network-registration.c \
			drivers/hfpmodem/call-volume.c \
			drivers/hfpmodem/devinfo.c \
			drivers/hfpmodem/handsfree.c \
			drivers/hfpmodem/siri.c

builtin_modules += speedupmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/speedupmodem/speedupmodem.h \
			drivers/speedupmodem/speedupmodem.c \
			drivers/speedupmodem/ussd.c

builtin_modules += ubloxmodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/ubloxmodem/ubloxmodem.h \
			drivers/ubloxmodem/ubloxmodem.c \
			drivers/ubloxmodem/gprs-context.c \
			drivers/ubloxmodem/netmon.c \
			drivers/ubloxmodem/lte.c


builtin_modules += gemaltomodem
builtin_sources += drivers/atmodem/atutil.h \
			include/gemalto.h \
			drivers/gemaltomodem/gemaltomodem.h \
			drivers/gemaltomodem/gemaltomodem.c \
			drivers/gemaltomodem/gemaltoutil.h \
			drivers/gemaltomodem/gemaltoutil.c \
			drivers/gemaltomodem/location-reporting.c \
			drivers/gemaltomodem/voicecall.c \
			drivers/gemaltomodem/lte.c \
			drivers/gemaltomodem/gprs-context-swwan-blocking.c \
			drivers/gemaltomodem/gprs-context-swwan.c \
			drivers/gemaltomodem/gprs-context-mbim.c

builtin_modules += ztevanillamodem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/ztevanillamodem/ztevanillamodem.h \
			drivers/ztevanillamodem/ztevanillamodem.c \
			drivers/ztevanillamodem/lte.c \
			drivers/ztevanillamodem/gprs-context.c

builtin_modules += xmm7modem
builtin_sources += drivers/atmodem/atutil.h \
			drivers/xmm7modem/xmm7modem.h \
			drivers/xmm7modem/xmm7modem.c \
			drivers/xmm7modem/radio-settings.c \
			drivers/xmm7modem/ims.c \
			drivers/xmm7modem/netmon.c

if PHONESIM
builtin_modules += phonesim
builtin_sources += plugins/phonesim.c

if DATAFILES
dist_conf_DATA += plugins/phonesim.conf
endif
endif

if CDMAMODEM
builtin_modules += cdmamodem
builtin_sources += drivers/cdmamodem/cdmamodem.h \
			drivers/cdmamodem/cdmamodem.c \
			drivers/cdmamodem/voicecall.c \
			drivers/cdmamodem/devinfo.c \
			drivers/cdmamodem/connman.c
endif

builtin_modules += g1
builtin_sources += plugins/g1.c

builtin_modules += wavecom
builtin_sources += plugins/wavecom.c

builtin_modules += calypso
builtin_sources += plugins/calypso.c

builtin_modules += mbm
builtin_sources += plugins/mbm.c

builtin_modules += hso
builtin_sources += plugins/hso.c

builtin_modules += zte
builtin_sources += plugins/zte.c

builtin_modules += zte_vanilla
builtin_sources += plugins/zte_vanilla.c

builtin_modules += huawei
builtin_sources += plugins/huawei.c

builtin_modules += sierra
builtin_sources += plugins/sierra.c

builtin_modules += novatel
builtin_sources += plugins/novatel.c

builtin_modules += palmpre
builtin_sources += plugins/palmpre.c

builtin_modules += ifx
builtin_sources += plugins/ifx.c

builtin_modules += ste
builtin_sources += plugins/ste.c

builtin_modules += stemgr
builtin_sources += plugins/stemgr.c

builtin_modules += caif
builtin_sources += plugins/caif.c

builtin_modules += gemalto
builtin_sources += plugins/gemalto.c

builtin_modules += nokia
builtin_sources += plugins/nokia.c

builtin_modules += nokiacdma
builtin_sources += plugins/nokiacdma.c

builtin_modules += linktop
builtin_sources += plugins/linktop.c

builtin_modules += icera
builtin_sources += plugins/icera.c

builtin_modules += alcatel
builtin_sources += plugins/alcatel.c

builtin_modules += speedup
builtin_sources += plugins/speedup.c

builtin_modules += speedupcdma
builtin_sources += plugins/speedupcdma.c

builtin_modules += samsung
builtin_sources += plugins/samsung.c

builtin_modules += sim900
builtin_sources += plugins/sim900.c

builtin_modules += sim7100
builtin_sources += plugins/sim7100.c

builtin_modules += connman
builtin_sources += plugins/connman.c

builtin_modules += telit
builtin_sources += plugins/telit.c

builtin_modules += quectel
builtin_sources += plugins/quectel.c

builtin_modules += ublox
builtin_sources += plugins/ublox.c

builtin_modules += xmm7xxx
builtin_sources += plugins/xmm7xxx.c

if BLUETOOTH
if BLUEZ4
builtin_modules += sap
builtin_sources += plugins/sap.c plugins/bluez4.h

builtin_modules += hfp_bluez4
builtin_sources += plugins/hfp_hf_bluez4.c plugins/bluez4.h

builtin_modules += dun_gw_bluez4
builtin_sources += plugins/dun_gw_bluez4.c plugins/bluez4.h
else
builtin_modules += hfp_bluez5
builtin_sources += plugins/hfp_hf_bluez5.c plugins/bluez5.h

builtin_modules += dun_gw_bluez5
builtin_sources += plugins/dun_gw_bluez5.c plugins/bluez5.h
endif
endif
endif

if BLUETOOTH
if BLUEZ4
builtin_modules += bluez4
builtin_sources += plugins/bluez4.c plugins/bluez4.h

builtin_modules += hfp_ag_bluez4
builtin_sources += plugins/hfp_ag_bluez4.c plugins/bluez4.h

builtin_sources += $(btio_sources)
builtin_cflags += @BLUEZ_CFLAGS@
builtin_libadd += @BLUEZ_LIBS@
else
builtin_modules += bluez5
builtin_sources += plugins/bluez5.c plugins/bluez5.h

builtin_modules += hfp_ag_bluez5
builtin_sources += plugins/hfp_ag_bluez5.c plugins/bluez5.h
endif

if UPOWER
builtin_modules += upower
builtin_sources += plugins/upower.c
endif
endif

if PROVISION
builtin_sources += plugins/mbpi.h plugins/mbpi.c

builtin_modules += provision
builtin_sources += plugins/provision.c

builtin_modules += cdma_provision
builtin_sources += plugins/cdma-provision.c

builtin_modules += file_provision
builtin_sources += plugins/file-provision.c

endif

if MAINTAINER_MODE
builtin_modules += example_history
builtin_sources += examples/history.c

builtin_modules += example_nettime
builtin_sources += examples/nettime.c

builtin_modules += example_provision
builtin_sources += examples/provision.c

builtin_modules += example_emulator
builtin_sources += examples/emulator.c

builtin_modules += example_private_network
builtin_sources += examples/private-network.c

builtin_modules += stktest
builtin_sources += plugins/stktest.c

builtin_modules += emulator_fuzz
builtin_sources += plugins/emulator_fuzz.c
endif

builtin_modules += smart_messaging
builtin_sources += plugins/smart-messaging.c

builtin_modules += push_notification
builtin_sources += plugins/push-notification.c

builtin_modules += allowed_apns
builtin_sources += plugins/allowed-apns.c

sbin_PROGRAMS = src/ofonod

src_ofonod_SOURCES = $(builtin_sources) $(gatchat_sources) src/ofono.ver \
			src/main.c src/ofono.h src/log.c src/plugin.c \
			src/modem.c src/common.h src/common.c \
			src/manager.c src/dbus.c src/util.h src/util.c \
			src/network.c src/voicecall.c src/ussd.c src/sms.c \
			src/call-settings.c src/call-forwarding.c \
			src/call-meter.c src/smsutil.h src/smsutil.c \
			src/call-barring.c src/sim.c src/stk.c \
			src/phonebook.c src/history.c src/message-waiting.c \
			src/simutil.h src/simutil.c src/storage.h \
			src/storage.c src/cbs.c src/watch.c src/call-volume.c \
			src/gprs.c src/idmap.h src/idmap.c \
			src/radio-settings.c src/stkutil.h src/stkutil.c \
			src/nettime.c src/stkagent.c src/stkagent.h \
			src/simfs.c src/simfs.h src/audio-settings.c \
			src/smsagent.c src/smsagent.h src/ctm.c \
			src/cdma-voicecall.c src/sim-auth.c \
			src/message.h src/message.c src/gprs-provision.c \
			src/emulator.c src/location-reporting.c \
			src/cdma-connman.c src/gnss.c \
			src/gnssagent.c src/gnssagent.h \
			src/cdma-smsutil.h src/cdma-smsutil.c \
			src/cdma-sms.c src/private-network.c src/cdma-netreg.c \
			src/cdma-provision.c src/handsfree.c \
			src/handsfree-audio.c src/bluetooth.h \
			src/hfp.h src/siri.c \
			src/netmon.c src/lte.c src/ims.c \
			src/netmonagent.c src/netmonagent.h

src_ofonod_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) $(ell_ldadd) \
			@GLIB_LIBS@ @DBUS_LIBS@ -ldl

src_ofonod_LDFLAGS = -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/ofono.ver

src_ofonod_DEPENDENCIES = $(ell_dependencies)

BUILT_SOURCES = $(local_headers) $(ell_built_sources) src/builtin.h

CLEANFILES = $(BUILT_SOURCES) $(rules_DATA)

plugindir = $(pkglibdir)/plugins

if MAINTAINER_MODE
build_plugindir = $(abs_top_srcdir)/plugins/.libs
else
build_plugindir = $(plugindir)
endif

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ $(ell_cflags) $(builtin_cflags) \
					-DOFONO_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(build_plugindir)"\"

AM_CPPFLAGS = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/src \
			-I$(srcdir)/gdbus -I$(srcdir)/gisi -I$(srcdir)/gatchat \
			-I$(srcdir)/btio -I$(srcdir)/gril

doc_files = doc/overview.txt doc/ofono-paper.txt doc/release-faq.txt \
		doc/manager-api.txt doc/modem-api.txt doc/network-api.txt \
			doc/voicecallmanager-api.txt doc/voicecall-api.txt \
			doc/call-forwarding-api.txt doc/call-settings-api.txt \
			doc/call-meter-api.txt doc/call-barring-api.txt \
			doc/supplementaryservices-api.txt \
			doc/connman-api.txt doc/features.txt \
			doc/pushnotification-api.txt \
			doc/smartmessaging-api.txt \
			doc/call-volume-api.txt doc/cell-broadcast-api.txt \
			doc/messagemanager-api.txt doc/message-waiting-api.txt \
			doc/phonebook-api.txt doc/radio-settings-api.txt \
			doc/sim-api.txt doc/stk-api.txt \
			doc/audio-settings-api.txt doc/text-telephony-api.txt \
			doc/calypso-modem.txt doc/message-api.txt \
			doc/location-reporting-api.txt \
			doc/certification.txt doc/siri-api.txt \
			doc/telit-modem.txt \
			doc/networkmonitor-api.txt \
			doc/allowed-apns-api.txt \
			doc/lte-api.txt \
			doc/gemalto-hardware-monitor-api.txt \
			doc/ims-api.txt


test_scripts = test/backtrace \
		test/create-internet-context \
		test/create-mms-context \
		test/activate-context \
		test/deactivate-context \
		test/deactivate-all \
		test/dial-number \
		test/list-calls \
		test/answer-calls \
		test/reject-calls \
		test/create-multiparty \
		test/private-chat \
		test/disable-modem \
		test/enable-modem \
		test/enter-pin \
		test/reset-pin \
		test/hangup-all \
		test/hangup-active \
		test/set-mms-details \
		test/set-roaming-allowed \
		test/list-contexts \
		test/list-modems \
		test/list-operators \
		test/scan-for-operators \
		test/get-operators\
		test/monitor-ofono \
		test/process-context-settings \
		test/receive-sms \
		test/remove-contexts \
		test/send-sms \
		test/cancel-sms \
		test/set-mic-volume \
		test/set-speaker-volume \
		test/test-stk-menu \
		test/test-advice-of-charge \
		test/test-call-barring \
		test/test-call-forwarding \
		test/test-call-settings \
		test/test-modem \
		test/test-network-registration \
		test/test-phonebook \
		test/test-cbs \
		test/test-ss \
		test/test-ss-control-cb \
		test/test-ss-control-cf \
		test/test-ss-control-cs \
		test/send-ussd \
		test/cancel-ussd \
		test/initiate-ussd \
		test/offline-modem \
		test/online-modem \
		test/get-tech-preference \
		test/set-tech-preference \
		test/set-use-sms-reports \
		test/set-cbs-topics \
		test/enable-cbs \
		test/lock-pin \
		test/unlock-pin \
		test/change-pin \
		test/enable-gprs \
		test/disable-gprs \
		test/get-icon \
		test/set-fast-dormancy \
		test/test-push-notification \
		test/test-smart-messaging \
		test/send-vcard \
		test/send-vcal \
		test/set-tty \
		test/set-gsm-band \
		test/set-umts-band \
		test/lockdown-modem \
		test/set-call-forwarding \
		test/cdma-list-call \
		test/cdma-dial-number \
		test/cdma-hangup \
		test/cdma-set-credentials \
		test/disable-call-forwarding \
		test/list-messages \
		test/test-sms \
		test/test-message-waiting \
		test/cdma-connman-disable \
		test/cdma-connman-enable \
		test/set-context-property \
		test/test-gnss \
		test/swap-calls \
		test/release-and-answer \
		test/release-and-swap \
		test/hold-and-answer \
		test/hangup-multiparty \
		test/hangup-call \
		test/display-icon \
		test/set-msisdn \
		test/set-ddr \
		test/register-auto \
		test/register-operator \
		test/set-sms-smsc \
		test/set-sms-bearer \
		test/get-serving-cell-info \
		test/list-allowed-access-points \
		test/enable-throttling \
		test/disable-throttling \
		test/set-lte-property \
		test/test-serving-cell-info \
		test/ims-register \
		test/ims-unregister \
		test/list-applications \
		test/set-sms-alphabet


if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

EXTRA_DIST = src/genbuiltin plugins/ofono.rules plugins/ofono-speedup.rules \
				$(doc_files) $(test_scripts)

dist_man_MANS = doc/ofonod.8


unit_objects =

unit_tests = unit/test-common unit/test-util \
				unit/test-simutil unit/test-stkutil \
				unit/test-sms unit/test-cdmasms \
				unit/test-mbim \
				unit/test-rilmodem-cs \
				unit/test-rilmodem-sms \
				unit/test-rilmodem-cb \
				unit/test-rilmodem-gprs

noinst_PROGRAMS = $(unit_tests) \
			unit/test-sms-root unit/test-mux unit/test-caif

unit_test_common_SOURCES = unit/test-common.c src/common.c src/util.c
unit_test_common_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_common_OBJECTS)

unit_test_util_SOURCES = unit/test-util.c src/util.c
unit_test_util_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_utils_OBJECTS)

unit_test_simutil_SOURCES = unit/test-simutil.c src/util.c \
                                src/simutil.c src/smsutil.c src/storage.c
unit_test_simutil_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_simutil_OBJECTS)

unit_test_stkutil_SOURCES = unit/test-stkutil.c unit/stk-test-data.h \
				src/util.c \
                                src/storage.c src/smsutil.c \
                                src/simutil.c src/stkutil.c
unit_test_stkutil_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_stkutil_OBJECTS)

unit_test_sms_SOURCES = unit/test-sms.c src/util.c src/smsutil.c src/storage.c
unit_test_sms_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_sms_OBJECTS)

unit_test_cdmasms_SOURCES = unit/test-cdmasms.c src/cdma-smsutil.c
unit_test_cdmasms_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_cdmasms_OBJECTS)

unit_test_sms_root_SOURCES = unit/test-sms-root.c \
					src/util.c src/smsutil.c src/storage.c
unit_test_sms_root_LDADD = @GLIB_LIBS@ $(ell_ldadd)
unit_objects += $(unit_test_sms_root_OBJECTS)

unit_test_mux_SOURCES = unit/test-mux.c $(gatchat_sources)
unit_test_mux_LDADD = @GLIB_LIBS@
unit_objects += $(unit_test_mux_OBJECTS)

unit_test_caif_SOURCES = unit/test-caif.c $(gatchat_sources) \
					drivers/stemodem/caif_socket.h \
					drivers/stemodem/if_caif.h
unit_test_caif_LDADD = @GLIB_LIBS@
unit_objects += $(unit_test_caif_OBJECTS)

test_rilmodem_sources = $(gril_sources) src/log.c src/common.c src/util.c \
				gatchat/ringbuffer.h gatchat/ringbuffer.c \
				unit/rilmodem-test-server.h \
				unit/rilmodem-test-server.c \
				unit/rilmodem-test-engine.h \
				unit/rilmodem-test-engine.c \
				src/simutil.c \
				drivers/rilmodem/rilutil.c

unit_test_rilmodem_cs_SOURCES = $(test_rilmodem_sources) \
					unit/test-rilmodem-cs.c \
					drivers/rilmodem/call-settings.c
unit_test_rilmodem_cs_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) \
					@GLIB_LIBS@ @DBUS_LIBS@ \
					$(ell_ldadd) -ldl
unit_objects += $(unit_test_rilmodem_cs_OBJECTS)

unit_test_rilmodem_sms_SOURCES = $(test_rilmodem_sources) \
					unit/test-rilmodem-sms.c \
					drivers/rilmodem/sms.c
unit_test_rilmodem_sms_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) \
					@GLIB_LIBS@ @DBUS_LIBS@ \
					$(ell_ldadd) -ldl
unit_objects += $(unit_test_rilmodem_sms_OBJECTS)

unit_test_rilmodem_cb_SOURCES = $(test_rilmodem_sources) \
					unit/test-rilmodem-cb.c \
					drivers/rilmodem/call-barring.c
unit_test_rilmodem_cb_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) \
					@GLIB_LIBS@ @DBUS_LIBS@ \
					$(ell_ldadd) -ldl
unit_objects += $(unit_test_rilmodem_cb_OBJECTS)

unit_test_rilmodem_gprs_SOURCES = $(test_rilmodem_sources) \
					unit/test-rilmodem-gprs.c \
					drivers/rilmodem/gprs.c
unit_test_rilmodem_gprs_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) \
					@GLIB_LIBS@ @DBUS_LIBS@ \
					$(ell_ldadd) -ldl
unit_objects += $(unit_test_rilmodem_gprs_OBJECTS)

unit_test_mbim_SOURCES = unit/test-mbim.c \
			 drivers/mbimmodem/mbim-message.c \
			 drivers/mbimmodem/mbim.c
unit_test_mbim_LDADD = $(ell_ldadd)
unit_objects += $(unit_test_mbim_OBJECTS)

TESTS = $(unit_tests)

if TOOLS
noinst_PROGRAMS += tools/huawei-audio tools/auto-enable \
			tools/get-location tools/lookup-apn \
			tools/lookup-provider-name tools/tty-redirector

tools_huawei_audio_SOURCES = tools/huawei-audio.c
tools_huawei_audio_LDADD = gdbus/libgdbus-internal.la @GLIB_LIBS@ @DBUS_LIBS@

tools_auto_enable_SOURCES = tools/auto-enable.c
tools_auto_enable_LDADD = gdbus/libgdbus-internal.la @GLIB_LIBS@ @DBUS_LIBS@

tools_get_location_SOURCES = tools/get-location.c
tools_get_location_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

tools_lookup_apn_SOURCES = plugins/mbpi.c plugins/mbpi.h tools/lookup-apn.c
tools_lookup_apn_LDADD = @GLIB_LIBS@

tools_lookup_provider_name_SOURCES = plugins/mbpi.c plugins/mbpi.h \
				tools/lookup-provider-name.c
tools_lookup_provider_name_LDADD = @GLIB_LIBS@

tools_tty_redirector_SOURCES = tools/tty-redirector.c
tools_tty_redirector_LDADD = @GLIB_LIBS@

if MAINTAINER_MODE
noinst_PROGRAMS += tools/stktest

tools_stktest_SOURCES = $(gatchat_sources) tools/stktest.c \
				unit/stk-test-data.h
tools_stktest_LDADD = gdbus/libgdbus-internal.la @GLIB_LIBS@ @DBUS_LIBS@
endif
endif

if BLUETOOTH
if DUNDEE
sbin_PROGRAMS += dundee/dundee

dundee_common_sources = $(gatchat_sources) \
			src/log.c src/dbus.c dundee/dundee.h dundee/main.c \
			dundee/dbus.c dundee/manager.c dundee/device.c

dundee_dundee_LDADD = $(builtin_libadd) gdbus/libgdbus-internal.la \
			@GLIB_LIBS@ @DBUS_LIBS@ -ldl

if DATAFILES
dist_dbusconf_DATA += dundee/dundee.conf

if SYSTEMD
systemdunit_DATA += dundee/dundee.service
endif
endif

if BLUEZ4
dundee_dundee_SOURCES = $(dundee_common_sources) $(btio_sources) \
			plugins/bluez4.c dundee/bluez4.c
else
dundee_dundee_SOURCES = $(dundee_common_sources) plugins/bluez5.c \
			dundee/bluez5.c
endif
endif
endif

noinst_PROGRAMS += gatchat/gsmdial gatchat/test-server gatchat/test-qcdm

gatchat_gsmdial_SOURCES = gatchat/gsmdial.c $(gatchat_sources)
gatchat_gsmdial_LDADD = @GLIB_LIBS@

gatchat_test_server_SOURCES = gatchat/test-server.c $(gatchat_sources)
gatchat_test_server_LDADD = @GLIB_LIBS@ -lutil

gatchat_test_qcdm_SOURCES = gatchat/test-qcdm.c $(gatchat_sources)
gatchat_test_qcdm_LDADD = @GLIB_LIBS@


DISTCHECK_CONFIGURE_FLAGS = --disable-datafiles \
				--enable-dundee --enable-tools

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs


src/builtin.h: src/genbuiltin config.status
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

plugins/%.rules:
	$(AM_V_GEN)cp $(srcdir)/$(subst 97-,,$@) $@

include/ofono/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/ofono
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/ofono/%.h: $(abs_top_srcdir)/include/%.h
	$(AM_V_at)$(MKDIR_P) include/ofono
	$(AM_V_GEN)$(LN_S) $< $@

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_headers) $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/ell.h: Makefile
	$(AM_V_at)echo -n > $@
	$(AM_V_GEN)for f in $(ell_headers) ; do \
		echo "#include <$$f>" >> $@ ; \
	done

maintainer-clean-local:
	-rm -rf ell

clean-local:
	@$(RM) -rf include/ofono
