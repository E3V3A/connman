/*
 *  Connection Manager
 *
 *  Copyright (C) 2015-2016 Jolla Ltd. All rights reserved.
 *  Contact: Slava Monich <slava.monich@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gofono_manager.h>
#include <gofono_modem.h>
#include <gofono_netreg.h>
#include <gofono_simmgr.h>
#include <gofono_connmgr.h>
#include <gofono_connctx.h>
#include <gofono_util.h>
#include <gofonoext_mm.h>
#include <gutil_log.h>

#include <errno.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/log.h>
#include <connman/technology.h>

#include "connman.h"

enum mm_handler_id {
	MM_HANDLER_VALID,
	MM_HANDLER_DATA_MODEM,
	MM_HANDLER_COUNT
};

enum manager_handler_id {
	MANAGER_HANDLER_VALID,
	MANAGER_HANDLER_MODEM_ADDED,
	MANAGER_HANDLER_MODEM_REMOVED,
	MANAGER_HANDLER_COUNT
};

enum modem_handler_id {
	MODEM_HANDLER_VALID,
	MODEM_HANDLER_POWERED,
	MODEM_HANDLER_ONLINE,
	MODEM_HANDLER_COUNT
};

enum netreg_handler_id {
	NETREG_HANDLER_VALID,
	NETREG_HANDLER_STATUS,
	NETREG_HANDLER_MCC,
	NETREG_HANDLER_MNC,
	NETREG_HANDLER_STRENGTH,
	NETREG_HANDLER_NAME,
	NETREG_HANDLER_COUNT
};

enum simmgr_handler_id {
	SIMMGR_HANDLER_VALID,
	SIMMGR_HANDLER_IMSI,
	SIMMGR_HANDLER_COUNT
};

enum connmgr_handler_id {
	CONNMGR_HANDLER_VALID,
	CONNMGR_HANDLER_ATTACHED,
	CONNMGR_HANDLER_CONTEXT_ADDED,
	CONNMGR_HANDLER_CONTEXT_REMOVED,
	CONNMGR_HANDLER_COUNT
};

enum connctx_handler_id {
	CONNCTX_HANDLER_VALID,
	CONNCTX_HANDLER_ACTIVE,
	CONNCTX_HANDLER_FAILED,
	CONNCTX_HANDLER_SETTINGS,
	CONNCTX_HANDLER_IPV6_SETTINGS,
	CONNCTX_HANDLER_COUNT
};

/* Should be less than CONNECT_TIMEOUT defined in service.c (currently 120) */
#define ACTIVATE_TIMEOUT_SEC (60)
#define ONLINE_CHECK_SEC  (2)

struct modem_data {
	OfonoModem *modem;
	OfonoNetReg *netreg;
	OfonoSimMgr *simmgr;
	OfonoConnMgr *connmgr;
	OfonoConnCtx *connctx;
	OfonoExtModemManager *mm;
	gulong modem_handler_id[MODEM_HANDLER_COUNT];
	gulong netreg_handler_id[NETREG_HANDLER_COUNT];
	gulong simmgr_handler_id[SIMMGR_HANDLER_COUNT];
	gulong connmgr_handler_id[CONNMGR_HANDLER_COUNT];
	gulong connctx_handler_id[CONNCTX_HANDLER_COUNT];
	guint activate_timeout_id;
	guint online_check_id;
	struct connman_device *device;
	struct connman_network *network;
	const char *country;
	gboolean roaming;
	gboolean enabled;
	guint strength;
	char *name;
	char *imsi;
};

struct plugin_data {
	OfonoExtModemManager *mm;
	OfonoManager *manager;
	GHashTable *modems;
	gulong mm_handler_id[MM_HANDLER_COUNT];
	gulong manager_handler_id[MANAGER_HANDLER_COUNT];
};

static void connctx_update_active(struct modem_data *md);
static void modem_update_network(struct modem_data *md);
static void modem_online_check(struct modem_data *md);

static void connctx_remove_handler(struct modem_data *md,
						enum connctx_handler_id id)
{
	if (md->connctx_handler_id[id]) {
		ofono_connctx_remove_handler(md->connctx,
			md->connctx_handler_id[id]);
		md->connctx_handler_id[id] = 0;
	}
}

static void connctx_activate_failed(OfonoConnCtx *ctx, const GError *err,
								void *arg)
{
	struct modem_data *md = arg;
	DBG("%s failed", ofono_modem_path(md->modem));
	GASSERT(data->connctx_handler_id[CONNCTX_HANDLER_FAILED]);
	connctx_update_active(md);
}

/* Handles both activation and deactivation timeouts */
static gboolean connctx_activate_timeout(gpointer data)
{
	struct modem_data *md = data;
	DBG("%s", ofono_modem_path(md->modem));
	GASSERT(md->activate_timeout_id);
	md->activate_timeout_id = 0;
	connctx_update_active(md);
	return G_SOURCE_REMOVE;
}

static void connctx_activate_cancel(struct modem_data *md)
{
	connctx_remove_handler(md, CONNCTX_HANDLER_FAILED);
	if (md->activate_timeout_id) {
		DBG("%s done", ofono_modem_path(md->modem));
		g_source_remove(md->activate_timeout_id);
		md->activate_timeout_id = 0;
	}
}

static void connctx_activate_restart_timer(struct modem_data *md)
{
	if (md->activate_timeout_id) {
		g_source_remove(md->activate_timeout_id);
	}
	md->activate_timeout_id =
			g_timeout_add_seconds(ACTIVATE_TIMEOUT_SEC,
					connctx_activate_timeout, md);
}

static int ofono_network_probe(struct connman_network *network)
{
	struct modem_data *md = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(md->modem), network);
	return 0;
}

static void ofono_network_remove(struct connman_network *network)
{
	/*
	 * ofono_network_remove can be invoked spontaneously by connman
	 * if the associated network interface disappears.
	 */
	struct modem_data *md = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(md->modem), network);
	if (md->connctx) {
		/* Make sure mobile data gets disconnected */
		ofono_connctx_deactivate(md->connctx);
		if (md->connctx->active) {
			connctx_activate_restart_timer(md);
		}
	}
	if (md->network) {
		connman_network_unref(md->network);
		md->network = NULL;
	}
}

static int ofono_network_connect(struct connman_network *network)
{
	struct modem_data *md = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(md->modem), network);
	connctx_activate_cancel(md);
	if (md->connctx) {
		/*
		 * Refuse to connect mobile data if the cellular service
		 * is not autoconnectable. The AutoConnect property in the
		 * Sailfish UI is presented to users as on/off switch for
		 * mobile data. Let's interpret it as such.
		 *
		 * Strictly speaking, the value of the AutoConnect property
		 * isn't equal to service->autconnect, as one might think.
		 * It's actually service->favorite && service->autoconnect,
		 * but we only need to check service->autoconnect because
		 * for whatever reason favorite becomes true only after
		 * the service has been connected at least once.
		 */
		struct connman_service *service =
			connman_service_lookup_from_network(network);
		if (service && connman_service_get_autoconnect(service)) {
			ofono_connctx_activate(md->connctx);
			if (md->connctx->active) {
				/* Already connected */
				return 0;
			} else {
				md->connctx_handler_id[CONNCTX_HANDLER_FAILED] =
				ofono_connctx_add_activate_failed_handler(
					md->connctx, connctx_activate_failed,
					md);
				connctx_activate_restart_timer(md);
				/* Asynchronous connection */
				return (-EINPROGRESS);
			}
		} else {
			connman_warn("Refusing to connect mobile data");
			return (-EACCES);
		}
	} else {
		return (-ENOSYS);
	}
}

static int ofono_network_disconnect(struct connman_network *network)
{
	struct modem_data *md = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(md->modem), network);
	if (md->connctx) {
		ofono_connctx_deactivate(md->connctx);
		if (!md->connctx->active) {
			return 0;
		} else {
			connctx_activate_restart_timer(md);
			return (-EINPROGRESS);
		}
	} else {
		return -ENOSYS;
	}
}

static struct connman_network_driver ofono_network_driver = {
	.name           = "cellular",
	.type           = CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe          = ofono_network_probe,
	.remove         = ofono_network_remove,
	.connect        = ofono_network_connect,
	.disconnect     = ofono_network_disconnect,
};

static int ofono_device_probe(struct connman_device *device)
{
	struct modem_data *md = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(md->modem), device);
	return 0;
}

static void ofono_device_remove(struct connman_device *device)
{
	struct modem_data *md = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(md->modem), device);
}

static int ofono_device_enable(struct connman_device *device)
{
	struct modem_data *md = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(md->modem), device);
	md->enabled = TRUE;
	modem_update_network(md);
	return 0;
}

static int ofono_device_disable(struct connman_device *device)
{
	struct modem_data *md = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(md->modem), device);
	md->enabled = FALSE;
	modem_update_network(md);
	return 0;
}

static struct connman_device_driver ofono_device_driver = {
	.name           = "modem",
	.type           = CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe          = ofono_device_probe,
	.remove         = ofono_device_remove,
	.enable         = ofono_device_enable,
	.disable        = ofono_device_disable,
};

static const char *modem_ident(struct modem_data *md)
{
	const char *path = ofono_connctx_path(md->connctx);
	if (path && path[0] == '/') {
		const char *slash = strrchr(path, '/');
		if (slash) {
			return slash + 1;
		}
	}
	return NULL;
}

static void modem_create_device(struct modem_data *md)
{
	const char *path = ofono_modem_path(md->modem);
	const char *ident;
	char *tmp;

	GASSERT(!md->device);
	if (connman_dbus_validate_ident(md->imsi)) {
		tmp = NULL;
		ident = md->imsi;
	} else {
		tmp = connman_dbus_encode_string(md->imsi);
		ident = tmp;
	}

	md->device = connman_device_create("ofono",
						CONNMAN_DEVICE_TYPE_CELLULAR);

	DBG("%s device %p ident %s", path, md->device, ident);
	connman_device_set_ident(md->device, ident);
	connman_device_set_string(md->device, "Path", path);
	connman_device_set_data(md->device, md);
	connman_device_set_powered(md->device, md->enabled &&
							md->modem->online);
	if (connman_device_register(md->device)) {
		connman_error("Failed to register cellular device");
		connman_device_unref(md->device);
		md->device = NULL;
	}
	g_free(tmp);
}

static void modem_create_network(struct modem_data *md)
{
	const char *path = ofono_modem_path(md->modem);

	DBG("%s", path);
	GASSERT(md->device);
	GASSERT(!md->network);

	md->network = connman_network_create(path,
					CONNMAN_NETWORK_TYPE_CELLULAR);
	DBG("network %p", md->network);

	connman_network_set_data(md->network, md);
	connman_network_set_name(md->network, md->name ? md->name : "");
	connman_network_set_group(md->network, modem_ident(md));
	connman_network_set_strength(md->network, md->strength);
	connman_network_set_bool(md->network, "Roaming", md->roaming);
	connman_network_set_string(md->network, "Path", path);

	if (connman_device_add_network(md->device, md->network) == 0) {
		connctx_update_active(md);
	} else {
		connman_network_unref(md->network);
		md->network = NULL;
	}
}

static void modem_destroy_network(struct modem_data *md)
{
	if (md->network) {
		DBG("%s", ofono_modem_path(md->modem));
		connman_device_remove_network(md->device, md->network);
		if (md->network) {
			connman_network_unref(md->network);
			md->network = NULL;
		}
	}
}

static void modem_destroy_device(struct modem_data *md)
{
	if (md->device) {
		DBG("%s", ofono_modem_path(md->modem));
		connman_device_set_powered(md->device, FALSE);
		modem_destroy_network(md);
		connman_device_unregister(md->device);
		connman_device_unref(md->device);
		md->device = NULL;
	}
}

static gboolean modem_can_create_device(struct modem_data *md)
{
	return ofono_modem_valid(md->modem) && md->modem->powered &&
		ofono_simmgr_valid(md->simmgr) && md->imsi &&
		ofono_connmgr_valid(md->connmgr) && md->mm->valid &&
		ofono_modem_equal(md->mm->data_modem, md->modem);
}

static gboolean modem_can_create_network(struct modem_data *md)
{
	/*
	 * Don't create the network if cellular technology is disabled,
	 * otherwise connman will keep on trying to connect it.
	 */
	return md->enabled && md->device && md->connmgr->attached &&
		ofono_connctx_valid(md->connctx);
}

static void modem_update_device(struct modem_data *md)
{
	if (modem_can_create_device(md)) {
		if (md->device) {
			connman_device_set_powered(md->device, md->enabled &&
							md->modem->online);
		} else {
			modem_create_device(md);
		}
	} else {
		modem_destroy_device(md);
	}
}

static void modem_update_network(struct modem_data *md)
{
	modem_update_device(md);
	if (modem_can_create_network(md)) {
		if (!md->network) {
			modem_create_network(md);
		}
	} else {
		modem_destroy_network(md);
	}
}

static GString *modem_append_strv(GString *str, char *const *strv)
{
	if (strv) {
		while (*strv) {
			const char *s = *strv;
			if (s[0]) {
				if (!str) {
					str = g_string_new(NULL);
				} else if (str->len > 0) {
					g_string_append_c(str, ' ');
				}
				g_string_append(str, s);
			}
			strv++;
		}
	}
	return str;
}

static GString *modem_configure_ipv4(struct connman_network *network,
	const struct ofono_connctx_settings *config, GString *nameservers)
{
	if (config->method == OFONO_CONNCTX_METHOD_STATIC && config->address) {
		struct connman_ipaddress *ipaddr =
			connman_ipaddress_alloc(CONNMAN_IPCONFIG_TYPE_IPV4);
		connman_ipaddress_set_ipv4(ipaddr, config->address,
					config->netmask, config->gateway);
		connman_network_set_ipv4_method(network,
					CONNMAN_IPCONFIG_METHOD_FIXED);
		connman_network_set_ipaddress(network, ipaddr);
		connman_ipaddress_free(ipaddr);
	} else {
		connman_network_set_ipv4_method(network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
	}
	return modem_append_strv(nameservers, config->dns);
}

static GString *modem_configure_ipv6(struct connman_network *network,
	const struct ofono_connctx_settings *config, GString *nameservers)
{
	if (config->method == OFONO_CONNCTX_METHOD_DHCP) {
		connman_network_set_ipv6_method(network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
	} else if (config->address) {
		struct connman_ipaddress *ipaddr =
			connman_ipaddress_alloc(CONNMAN_IPCONFIG_TYPE_IPV6);
		connman_ipaddress_set_ipv6(ipaddr, config->address,
					config->prefix, config->gateway);
		connman_network_set_ipv6_method(network,
					CONNMAN_IPCONFIG_METHOD_FIXED);
		connman_network_set_ipaddress(network, ipaddr);
		connman_ipaddress_free(ipaddr);
	} else {
		connman_network_set_ipv6_method(network,
					CONNMAN_IPCONFIG_METHOD_AUTO);
	}
	return modem_append_strv(nameservers, config->dns);
}

static int modem_configure(struct modem_data *md)
{
	const int index = connman_inet_ifindex(md->connctx->ifname);
	struct connman_service *service =
		connman_service_lookup_from_network(md->network);

	if (index >= 0 && service) {
		GString *ns = NULL;

		DBG("%s %d", ofono_modem_path(md->modem), index);

		if (md->connctx->settings) {
			connman_service_create_ip4config(service, index);
			ns = modem_configure_ipv4(md->network,
					md->connctx->settings, ns);
		} else {
			connman_network_set_ipv4_method(md->network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
		}

		if (md->connctx->ipv6_settings) {
			connman_service_create_ip6config(service, index);
			ns = modem_configure_ipv6(md->network,
					md->connctx->ipv6_settings, ns);
		} else {
			connman_network_set_ipv6_method(md->network,
					CONNMAN_IPCONFIG_METHOD_AUTO);
		}

		if (ns) {
			connman_network_set_nameservers(md->network, ns->str);
			g_string_free(ns, TRUE);
		}
	}

	return index;
}

static void modem_connected(struct modem_data *md)
{
	const int index = modem_configure(md);

	if (index >= 0) {
		connman_network_set_index(md->network, index);
		connman_network_set_connected(md->network, TRUE);
	}
}

static void simmgr_changed(OfonoSimMgr *simmgr, void *arg)
{
	struct modem_data *md = arg;
	GASSERT(md->simmgr == simmgr);
	if (ofono_simmgr_valid(simmgr)) {
		DBG("%s %s", ofono_modem_path(md->modem), simmgr->imsi);
		if (g_strcmp0(simmgr->imsi, md->imsi)) {
			modem_destroy_device(md);
			g_free(md->imsi);
			md->imsi = g_strdup(simmgr->imsi);
		}
	} else {
		DBG("%s invalid", ofono_modem_path(md->modem));
		g_free(md->imsi);
		md->imsi = NULL;
	}
	modem_update_network(md);
}

static void modem_update_roaming(struct modem_data *md)
{
	const gboolean roaming = md->roaming;
	md->roaming = (ofono_netreg_valid(md->netreg) &&
			md->netreg->status == OFONO_NETREG_STATUS_ROAMING);
	if (md->network && md->roaming != roaming) {
		DBG("%d", md->roaming);
		connman_network_set_bool(md->network, "Roaming", md->roaming);
		connman_network_update(md->network);
	}
}

static void modem_update_strength(struct modem_data *md)
{
	const guint strength = md->strength;
	md->strength = ofono_netreg_valid(md->netreg) ? md->netreg->strength : 0;
	if (md->network && md->strength != strength) {
		DBG("%u", md->strength);
		connman_network_set_strength(md->network, md->strength);
		connman_network_update(md->network);
	}
}

static void modem_update_name(struct modem_data *md)
{
	const char *name = ofono_netreg_valid(md->netreg) ?
						md->netreg->name : "";
	if (g_strcmp0(md->name, name)) {
		DBG("%s", name);
		g_free(md->name);
		md->name = g_strdup(name);
		if (md->network) {
			connman_network_set_name(md->network, md->name);
		}
	}
}

static void modem_update_country(struct modem_data *md)
{
	const char *country = md->country;
	md->country = ofono_netreg_country(md->netreg);
	if (md->country && g_strcmp0(md->country, country)) {
		DBG("%s", md->country);
		connman_technology_set_regdom(md->country);
	}
}

static void connctx_valid_changed(OfonoConnCtx *connctx, void *arg)
{
	modem_update_network(arg);
}

static void connctx_update_active(struct modem_data *md)
{
	GASSERT(md->connctx);
	if (ofono_connctx_valid(md->connctx)) {
		if (md->connctx->active) {
			if (!md->enabled || !md->network) {
				/*
				 * Mobile data is not supposed to be
				 * connected.
				 */
				ofono_connctx_deactivate(md->connctx);
				if (md->connctx->active) {
					connctx_activate_restart_timer(md);
				}
			} else if (!connman_network_get_connected(
							 md->network)) {
				connctx_activate_cancel(md);
				modem_connected(md);
			}
		} else {
			connctx_activate_cancel(md);
			if (md->network) {
				connman_network_set_connected(md->network,
								FALSE);
			}
		}
	}
}

static void connctx_active_changed(OfonoConnCtx *connctx, void *arg)
{
	struct modem_data *md = arg;

	DBG("%s %d", ofono_modem_path(md->modem), connctx->active);
	connctx_update_active(md);
}

static void connctx_settings_changed(OfonoConnCtx *connctx, void *arg)
{
	modem_configure(arg);
}

static void modem_update_context(struct modem_data *md)
{
	OfonoConnCtx *ctx = ofono_connmgr_valid(md->connmgr) ?
		ofono_connmgr_get_context_for_type(md->connmgr,
					OFONO_CONNCTX_TYPE_INTERNET) : NULL;
	const char *old_path = ofono_connctx_path(md->connctx);
	const char *new_path = ofono_connctx_path(ctx);
	if (g_strcmp0(old_path, new_path)) {
		if (md->connctx) {
			modem_destroy_network(md);
			ofono_connctx_remove_handlers(md->connctx,
					md->connctx_handler_id,
					G_N_ELEMENTS(md->connctx_handler_id));
			ofono_connctx_unref(md->connctx);
		}
		md->connctx = ofono_connctx_ref(ctx);
		if (md->connctx) {
			DBG("%s", ofono_connctx_path(md->connctx));
			md->connctx_handler_id[CONNCTX_HANDLER_VALID] =
				ofono_connctx_add_valid_changed_handler(
					md->connctx, connctx_valid_changed,
					md);
			md->connctx_handler_id[CONNCTX_HANDLER_ACTIVE] =
				ofono_connctx_add_active_changed_handler(
					md->connctx, connctx_active_changed,
					md);
			md->connctx_handler_id[CONNCTX_HANDLER_SETTINGS] =
				ofono_connctx_add_settings_changed_handler(
					md->connctx, connctx_settings_changed,
					md);
			md->connctx_handler_id[CONNCTX_HANDLER_IPV6_SETTINGS] =
				ofono_connctx_add_ipv6_settings_changed_handler(
					md->connctx, connctx_settings_changed,
					md);
			connctx_update_active(md);
		} else {
			DBG("no internet context");
		}
	}
	modem_update_network(md);
}

static void connmgr_contexts_added(OfonoConnMgr *connmgr,
					OfonoConnCtx *context, void *arg)
{
	DBG("%s", ofono_connctx_path(context));
	modem_update_context(arg);
}

static void connmgr_contexts_removed(OfonoConnMgr *connmgr,
					const char *path, void *arg)
{
	DBG("%s", path);
	modem_update_context(arg);
}

static gboolean modem_online_check_timer(gpointer data)
{
	struct modem_data *md = data;
	md->online_check_id = 0;
	modem_online_check(md);
	return G_SOURCE_REMOVE;
}

static void modem_set_online(struct modem_data *md, gboolean online)
{
	OfonoModem *modem = md->modem;
	if (modem->online == online) {
		if (md->online_check_id) {
			DBG("%s is %sline", ofono_modem_path(modem),
						online ? "on" : "off");
			g_source_remove(md->online_check_id);
			md->online_check_id = 0;
		}
	} else if (!md->online_check_id) {
		DBG("%s going %sline", ofono_modem_path(modem),
						online ? "on" : "off");
		md->online_check_id = g_timeout_add_seconds(
						ONLINE_CHECK_SEC,
						modem_online_check_timer, md);
		ofono_modem_set_online(modem, online);
	}
}

static void modem_online_check(struct modem_data *md)
{
	modem_set_online(md, !__connman_technology_get_offlinemode());
}

static void modem_changed(OfonoModem *modem, void *arg)
{
	struct modem_data *md = arg;
	if (ofono_modem_valid(modem)) {
		DBG("%s powered %d online %d", ofono_modem_path(modem),
					modem->powered, modem->online);
		if (!modem->powered) {
			DBG("%s powering up", ofono_modem_path(modem));
			ofono_modem_set_powered(modem, TRUE);
		}

		/* Keep modem online state in sync with the offline mode */
		modem_online_check(md);
	}
	modem_update_network(arg);
}

static void netreg_status_changed(OfonoNetReg *netreg, void *arg)
{
	modem_update_roaming(arg);
}

static void netreg_strength_changed(OfonoNetReg *netreg, void *arg)
{
	modem_update_strength(arg);
}

static void netreg_name_changed(OfonoNetReg *netreg, void *arg)
{
	modem_update_name(arg);
}

static void netreg_network_changed(OfonoNetReg *netreg, void *arg)
{
	modem_update_country(arg);
}

static void connmgr_valid_changed(OfonoConnMgr *connmgr, void *arg)
{
	DBG("%s %d", ofono_connmgr_path(connmgr), ofono_connmgr_valid(connmgr));
	modem_update_context(arg);
}

static void connmgr_attached_changed(OfonoConnMgr *connmgr, void *arg)
{
	DBG("%s %d", ofono_connmgr_path(connmgr), connmgr->attached);
	modem_update_network(arg);
}

static void modem_create(struct plugin_data *plugin, OfonoModem *modem)
{
	const char *path = ofono_modem_path(modem);
	struct modem_data *md = g_new0(struct modem_data, 1);

	md->mm = ofonoext_mm_ref(plugin->mm);
	md->modem = ofono_modem_ref(modem);
	md->modem_handler_id[MODEM_HANDLER_VALID] =
		ofono_modem_add_valid_changed_handler(md->modem,
					modem_changed, md);
	md->modem_handler_id[MODEM_HANDLER_POWERED] =
		ofono_modem_add_powered_changed_handler(md->modem,
					modem_changed, md);
	md->modem_handler_id[MODEM_HANDLER_ONLINE] =
		ofono_modem_add_online_changed_handler(md->modem,
					modem_changed, md);

	md->netreg = ofono_netreg_new(path);
	md->netreg_handler_id[NETREG_HANDLER_VALID] =
		ofono_netreg_add_valid_changed_handler(md->netreg,
					netreg_status_changed, md);
	md->netreg_handler_id[NETREG_HANDLER_STATUS] =
		ofono_netreg_add_status_changed_handler(md->netreg,
					netreg_status_changed, md);
	md->netreg_handler_id[NETREG_HANDLER_MCC] =
		ofono_netreg_add_mcc_changed_handler(md->netreg,
					netreg_network_changed, md);
	md->netreg_handler_id[NETREG_HANDLER_MNC] =
		ofono_netreg_add_mnc_changed_handler(md->netreg,
					netreg_network_changed, md);
	md->netreg_handler_id[NETREG_HANDLER_STRENGTH] =
		ofono_netreg_add_strength_changed_handler(md->netreg,
					netreg_strength_changed, md);
	md->netreg_handler_id[NETREG_HANDLER_NAME] =
		ofono_netreg_add_strength_changed_handler(md->netreg,
					netreg_name_changed, md);

	md->simmgr = ofono_simmgr_new(path);
	md->simmgr_handler_id[SIMMGR_HANDLER_VALID] =
		ofono_simmgr_add_valid_changed_handler(md->simmgr,
					simmgr_changed, md);
	md->simmgr_handler_id[SIMMGR_HANDLER_IMSI] =
		ofono_simmgr_add_imsi_changed_handler(md->simmgr,
					simmgr_changed, md);

	md->connmgr = ofono_connmgr_new(path);
	md->connmgr_handler_id[CONNMGR_HANDLER_VALID] =
		ofono_connmgr_add_valid_changed_handler(md->connmgr,
					connmgr_valid_changed, md);
	md->connmgr_handler_id[CONNMGR_HANDLER_ATTACHED] =
		ofono_connmgr_add_attached_changed_handler(md->connmgr,
					connmgr_attached_changed, md);
	md->connmgr_handler_id[CONNMGR_HANDLER_CONTEXT_ADDED] =
		ofono_connmgr_add_context_added_handler(md->connmgr,
					connmgr_contexts_added, md);
	md->connmgr_handler_id[CONNMGR_HANDLER_CONTEXT_REMOVED] =
		ofono_connmgr_add_context_removed_handler(md->connmgr,
					connmgr_contexts_removed, md);

	md->imsi = g_strdup(md->simmgr->imsi);
	g_hash_table_replace(plugin->modems, g_strdup(path), md);

	if (ofono_modem_valid(modem)) {
		ofono_modem_set_powered(modem, TRUE);
		modem_online_check(md);
	}
	if (ofono_connmgr_valid(md->connmgr)) {
		modem_update_context(md);
	}
	modem_update_network(md);
	modem_update_roaming(md);
	modem_update_strength(md);
	modem_update_name(md);
	modem_update_country(md);
}

static void modem_delete(gpointer value)
{
	struct modem_data *md = value;

	DBG("%s", ofono_modem_path(md->modem));
	connctx_activate_cancel(md);
	if (md->online_check_id) {
		g_source_remove(md->online_check_id);
	}

	modem_destroy_device(md);
	ofonoext_mm_unref(md->mm);

	ofono_modem_remove_handlers(md->modem, md->modem_handler_id,
					G_N_ELEMENTS(md->modem_handler_id));
	ofono_modem_unref(md->modem);

	ofono_netreg_remove_handlers(md->netreg, md->netreg_handler_id,
					G_N_ELEMENTS(md->netreg_handler_id));
	ofono_netreg_unref(md->netreg);

	ofono_simmgr_remove_handlers(md->simmgr, md->simmgr_handler_id,
					G_N_ELEMENTS(md->simmgr_handler_id));
	ofono_simmgr_unref(md->simmgr);

	ofono_connmgr_remove_handlers(md->connmgr, md->connmgr_handler_id,
					G_N_ELEMENTS(md->connmgr_handler_id));
	ofono_connmgr_unref(md->connmgr);

	if (md->connctx) {
		ofono_connctx_deactivate(md->connctx);
		ofono_connctx_remove_handlers(md->connctx,
					md->connctx_handler_id,
					G_N_ELEMENTS(md->connctx_handler_id));
		ofono_connctx_unref(md->connctx);
	}

	g_free(md->name);
	g_free(md->imsi);
	g_free(md);
}

static void manager_valid(struct plugin_data *plugin)
{
	GPtrArray *modems = ofono_manager_get_modems(plugin->manager);
	guint i;

	GASSERT(plugin->manager->object.valid);
	GASSERT(!g_hash_table_size(plugin->modems));

	for (i=0; i<modems->len; i++) {
		OfonoModem *modem = modems->pdata[i];
		DBG("modem %s", modem->object.path);
		modem_create(plugin, modem);
	}
}

static void manager_valid_changed(OfonoManager *manager, void *arg)
{
	struct plugin_data *plugin = arg;
	DBG("%d", manager->valid);
	GASSERT(plugin->manager == manager);
	if (manager->valid) {
		manager_valid(plugin);
	} else {
		g_hash_table_remove_all(plugin->modems);
	}
}

static void modem_added(OfonoManager *manager, OfonoModem *modem, void *arg)
{
	struct plugin_data *plugin = arg;
	DBG("%s", ofono_modem_path(modem));
	modem_create(plugin, modem);
}

static void modem_removed(OfonoManager *manager, const char *path, void *arg)
{
	struct plugin_data *plugin = arg;
	DBG("%s", path);
	g_hash_table_remove(plugin->modems, path);
}

static void mm_changed(OfonoExtModemManager *mm, void *arg)
{
	GHashTableIter it;
	gpointer value;
	struct plugin_data *plugin = arg;

	DBG("valid %d path %s", plugin->mm->valid,
				ofono_modem_path(plugin->mm->data_modem));

	/* Unregister stale devices first */
	g_hash_table_iter_init(&it, plugin->modems);
	while (g_hash_table_iter_next(&it, NULL, &value)) {
		struct modem_data *md = value;
		if (!modem_can_create_device(md)) {
			modem_destroy_device(md);
		}
	}

	/* Then create new ones if necessary */
	g_hash_table_iter_init(&it, plugin->modems);
	while (g_hash_table_iter_next(&it, NULL, &value)) {
 		modem_update_network(value);
	}
}

static void ofono_plugin_set_online(struct plugin_data *plugin, gboolean online)
{
	GHashTableIter it;
	gpointer value;
	g_hash_table_iter_init(&it, plugin->modems);
	while (g_hash_table_iter_next(&it, NULL, &value)) {
		modem_set_online((struct modem_data *)value, online);
	}
}

static struct plugin_data *ofono_plugin_new(void)
{
	struct plugin_data *plugin = g_new0(struct plugin_data, 1);

	plugin->modems = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, modem_delete);

	plugin->mm = ofonoext_mm_new();
	plugin->mm_handler_id[MM_HANDLER_VALID] =
		ofonoext_mm_add_valid_changed_handler(plugin->mm,
					mm_changed, plugin);
	plugin->mm_handler_id[MM_HANDLER_DATA_MODEM] =
		ofonoext_mm_add_data_modem_changed_handler(plugin->mm,
					mm_changed, plugin);

	plugin->manager = ofono_manager_new();
	plugin->manager_handler_id[MANAGER_HANDLER_VALID] =
		ofono_manager_add_valid_changed_handler(plugin->manager,
					manager_valid_changed, plugin);
	plugin->manager_handler_id[MANAGER_HANDLER_MODEM_ADDED] =
		ofono_manager_add_modem_added_handler(plugin->manager,
					modem_added, plugin);
	plugin->manager_handler_id[MANAGER_HANDLER_MODEM_REMOVED] =
		ofono_manager_add_modem_removed_handler(plugin->manager,
					modem_removed, plugin);

	if (plugin->manager->valid) {
		manager_valid(plugin);
	}
	return plugin;
}

static void ofono_plugin_delete(struct plugin_data *plugin)
{
	if (plugin) {
		g_hash_table_destroy(plugin->modems);
		ofonoext_mm_remove_handlers(plugin->mm, plugin->mm_handler_id,
				G_N_ELEMENTS(plugin->mm_handler_id));
		ofonoext_mm_unref(plugin->mm);
		ofono_manager_remove_handlers(plugin->manager,
				plugin->manager_handler_id,
				G_N_ELEMENTS(plugin->manager_handler_id));
		ofono_manager_unref(plugin->manager);
		g_free(plugin);
	}
 }

static void ofono_plugin_log_notify(struct connman_debug_desc *desc)
{
	if (desc->flags & CONNMAN_DEBUG_FLAG_PRINT) {
		gofono_log.level = gofono_log.max_level;
	} else {
		gofono_log.level = gutil_log_default.level;
	}
	DBG("%s log level %d", gofono_log.name, gofono_log.level);
}

static struct plugin_data *ofono_plugin;

static int ofono_tech_probe(struct connman_technology *tech)
{
	DBG("");
	return 0;
}

static void ofono_tech_remove(struct connman_technology *tech)
{
	DBG("");
}

static void ofono_tech_set_offline(bool offline)
{
	DBG("%d", offline);
	ofono_plugin_set_online(ofono_plugin, !offline);
}

static struct connman_technology_driver ofono_tech_driver = {
	.name           = "cellular",
	.type           = CONNMAN_SERVICE_TYPE_CELLULAR,
	.probe          = ofono_tech_probe,
	.remove         = ofono_tech_remove,
	.set_offline    = ofono_tech_set_offline
};

static int jolla_ofono_init(void)
{
	int err;
	static struct connman_debug_desc ofono_debug_desc CONNMAN_DEBUG_ATTR = {
		.name = "gofono",
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_DEFAULT,
		.notify = ofono_plugin_log_notify
	};

	/* connman core calls openlog() */
	gutil_log_func = gutil_log_syslog;
	if (ofono_debug_desc.flags & CONNMAN_DEBUG_FLAG_PRINT) {
		gofono_log.level = GLOG_LEVEL_VERBOSE;
	}

	err = connman_network_driver_register(&ofono_network_driver);
	if (!err) {
		err = connman_device_driver_register(&ofono_device_driver);
		if (!err) {
			err = connman_technology_driver_register(
							&ofono_tech_driver);
			if (!err) {
				GASSERT(!ofono_plugin);
				ofono_plugin = ofono_plugin_new();
				DBG("ok");
				return 0;
			}
			connman_device_driver_unregister(&ofono_device_driver);
		}
		connman_network_driver_unregister(&ofono_network_driver);
	}

	DBG("error %d", err);
	return err;
}

static void jolla_ofono_exit(void)
{
	DBG("");
	GASSERT(ofono_plugin);
	ofono_plugin_delete(ofono_plugin);
	ofono_plugin = NULL;

	connman_technology_driver_unregister(&ofono_tech_driver);
	connman_device_driver_unregister(&ofono_device_driver);
	connman_network_driver_unregister(&ofono_network_driver);
}

CONNMAN_PLUGIN_DEFINE(jolla_ofono, "Jolla oFono plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, jolla_ofono_init, jolla_ofono_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
