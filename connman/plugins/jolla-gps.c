/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd.
 *  Contact: Aaron McCarthy <aaron.mccarthy@jollamobile.com>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/technology.h>
#include <connman/device.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define LOCATION_CONF_DIR  "/etc/location/"
#define LOCATION_CONF_FILE "/etc/location/location.conf"
#define LOCATION_CONF_GROUP "location"
#define LOCATION_CONF_GPSENABLED_KEY "gps\\enabled"
#define LOCATION_CONF_GPSENABLED_RESTORE_KEY "gps\\was_enabled"

static struct connman_device *jolla_gps_device;
static GFile *location_conf_dir;
static GFileMonitor *location_conf_monitor;

/*
 * We don't support changing the device powered state directly.
 * Instead, setting the global offline_mode will trigger changing power state.
 */
static int change_powered(bool powered)
{
    (void)powered;

    DBG("");

    return -EINVAL;
}

static int jolla_gps_enable(struct connman_device *device)
{
    (void)device;

    DBG("");

    return change_powered(TRUE);
}

static int jolla_gps_disable(struct connman_device *device)
{
    (void)device;

    DBG("");

    return change_powered(FALSE);
}

static int jolla_gps_probe(struct connman_device *device)
{
    (void)device;

    DBG("");

    return 0;
}

static void jolla_gps_remove(struct connman_device *device)
{
    (void)device;

    DBG("");
}

static struct connman_device_driver device_driver = {
    .name = "gps",
    .type = CONNMAN_DEVICE_TYPE_GPS,
    .probe = jolla_gps_probe,
    .remove = jolla_gps_remove,
    .enable = jolla_gps_enable,
    .disable = jolla_gps_disable
};

static int jolla_gps_tech_probe(struct connman_technology *technology)
{
    (void)technology;

    DBG("");

    return 0;
}

static void jolla_gps_tech_remove(struct connman_technology *technology)
{
    (void)technology;

    DBG("");
}

static void jolla_gps_tech_set_offline(bool offline)
{
    GFile *location_conf_file;
    GKeyFile *location_conf;
    gsize location_conf_size;
    gchar *location_conf_data;
    gchar *gpsEnabledValue;
    gchar *gpsEnabledRestoreValue;
    bool gpsEnabled;
    bool gpsEnabledRestore;

fprintf(stderr, "JOLLA_GPS_SET_OFFLINE: %s\n", offline ? "true" : "false");

    location_conf = g_key_file_new();
    if (!g_key_file_load_from_file(
            location_conf,
            LOCATION_CONF_FILE,
            G_KEY_FILE_KEEP_COMMENTS |
            G_KEY_FILE_KEEP_TRANSLATIONS,
            NULL)) {
        return;
    }

    gpsEnabledValue = g_key_file_get_string(
            location_conf,
            LOCATION_CONF_GROUP,
            LOCATION_CONF_GPSENABLED_KEY,
            NULL);
    gpsEnabled = g_strcmp0(gpsEnabledValue, "true") == 0; /* false if null */

    if (offline) {
        /* Entering flight mode.
         * Store the current gpsEnabled value then set gpsEnabled to false. */
        g_key_file_set_string(
                location_conf,
                LOCATION_CONF_GROUP,
                LOCATION_CONF_GPSENABLED_RESTORE_KEY,
                gpsEnabled ? "true" : "false");
        g_key_file_set_string(
                location_conf,
                LOCATION_CONF_GROUP,
                LOCATION_CONF_GPSENABLED_KEY,
                "false");
    } else {
        /* Exiting flight mode.
         * Restore the old gpsEnabled value (or false if key not found) */
        gpsEnabledRestoreValue = g_key_file_get_string(
                location_conf,
                LOCATION_CONF_GROUP,
                LOCATION_CONF_GPSENABLED_RESTORE_KEY,
                NULL);
        gpsEnabledRestore = g_strcmp0(gpsEnabledRestoreValue, "true") == 0;
        g_key_file_set_string(
                location_conf,
                LOCATION_CONF_GROUP,
                LOCATION_CONF_GPSENABLED_KEY,
                gpsEnabledRestore ? "true" : "false");
    }

    /* cannot use g_key_file_save_to_file() since it clobbers file permissions */
    location_conf_data = g_key_file_to_data(
            location_conf,
            &location_conf_size,
            NULL);
    if (location_conf_size > 0) {
        location_conf_file = g_file_new_for_path(LOCATION_CONF_FILE);
        if (g_file_replace_contents(
                    location_conf_file,
                    location_conf_data,
                    location_conf_size,
                    NULL,
                    false,
                    G_FILE_CREATE_NONE,
                    NULL,
                    NULL,
                    NULL) == TRUE) {
            connman_device_set_powered(jolla_gps_device, gpsEnabled);
        }
        g_object_unref(location_conf_file);
    }

    g_key_file_free (location_conf);
}

static struct connman_technology_driver tech_driver = {
    .name = "gps",
    .type = CONNMAN_SERVICE_TYPE_GPS,
    .probe = jolla_gps_tech_probe,
    .remove = jolla_gps_tech_remove,
    .set_offline = jolla_gps_tech_set_offline,
};

static void location_conf_changed(
        GFileMonitor     *monitor,
        GFile            *file,
        GFile            *other_file,
        GFileMonitorEvent event_type,
        gpointer          user_data)
{
    GKeyFile *location_conf;
    gchar *gpsEnabledValue;
    bool gpsEnabled;

    (void)monitor;
    (void)file;
    (void)other_file;
    (void)event_type;
    (void)user_data;

    DBG("");

    location_conf = g_key_file_new();
    if (!g_key_file_load_from_file(
            location_conf,
            LOCATION_CONF_FILE,
            G_KEY_FILE_KEEP_COMMENTS |
            G_KEY_FILE_KEEP_TRANSLATIONS,
            NULL)) {
        return;
    }

    gpsEnabledValue = g_key_file_get_string(
            location_conf,
            LOCATION_CONF_GROUP,
            LOCATION_CONF_GPSENABLED_KEY,
            NULL);
    gpsEnabled = g_strcmp0(gpsEnabledValue, "true") == 0;

fprintf(stderr, "JOLLA_GPS_CONF_CHANGED: %s\n", gpsEnabled ? "true" : "false");

    g_key_file_free (location_conf);

    connman_device_set_powered(jolla_gps_device, gpsEnabled);
}

static int jolla_gps_init()
{
    DBG("");

    /* Watch location.conf file for changes which should be reflected
     * as the power state of the jolla-gps device to connman */
    location_conf_dir = g_file_new_for_path(LOCATION_CONF_DIR);
    location_conf_monitor = g_file_monitor_directory(
            location_conf_dir, G_FILE_MONITOR_NONE, NULL, NULL);
    g_signal_connect(location_conf_monitor, "changed",
                     G_CALLBACK(location_conf_changed), NULL);

    if (connman_technology_driver_register(&tech_driver) < 0) {
        connman_warn("Failed to initialize technology for Jolla GPS");
        g_file_monitor_cancel(location_conf_monitor);
        return -EIO;
    }

    if (connman_device_driver_register(&device_driver) < 0) {
        connman_warn("Failed to initialize device driver for Jolla GPS");
        connman_technology_driver_unregister(&tech_driver);
        g_file_monitor_cancel(location_conf_monitor);
        return -EIO;
    }

    jolla_gps_device = connman_device_create("gps", CONNMAN_DEVICE_TYPE_GPS);
    if (jolla_gps_device == NULL) {
        connman_warn("Failed to create GPS device");
        return -ENODEV;
    }

    if (connman_device_register(jolla_gps_device) < 0) {
        connman_warn("Failed to register GPS device");
        connman_device_unref(jolla_gps_device);
        jolla_gps_device = NULL;
        return -EIO;
    }

    return 0;
}

static void jolla_gps_exit()
{
    DBG("");

    if (jolla_gps_device != NULL) {
        connman_device_unregister(jolla_gps_device);
        connman_device_unref(jolla_gps_device);
        jolla_gps_device = NULL;
    }

    connman_device_driver_unregister(&device_driver);
    connman_technology_driver_unregister(&tech_driver);

    g_file_monitor_cancel(location_conf_monitor);
    g_object_unref(location_conf_monitor);
}

CONNMAN_PLUGIN_DEFINE(jolla_gps, "Jolla GPS", VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
                      jolla_gps_init, jolla_gps_exit)
