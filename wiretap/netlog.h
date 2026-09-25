/** @file
 *
 * Wiretap Library
 * Copyright (c) 2025 by Moshe Kaplan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETLOG_H__
#define __NETLOG_H__

#include "wtap.h"

/* Copyable pcapng custom string option, using PEN_WIRESHARK. The prefix
 * identifies the schema independently of other options using that PEN.
 * Each option is a snapshot of one related URL_REQUEST, not byte ownership.
 */
#define NETLOG_REQUEST_OPTION_PREFIX "netlog.request.v1:"

#define NETLOG_REQUEST_STRING_FIELDS(X) \
    X(url, "URL") \
    X(method, "Method") \
    X(initiator, "Initiator") \
    X(request_type, "Request type") \
    X(site_for_cookies, "Site for cookies") \
    X(priority, "Priority") \
    X(network_isolation_key, "Network isolation key") \
    X(network_anonymization_key, "Network anonymization key")

#define NETLOG_REQUEST_INT_FIELDS(X) \
    X(load_flags, "Load flags") \
    X(upload_id, "Upload ID")

/**
 * @brief Open a NetLog file for reading.
 *
 * @param wth Pointer to the wtap structure
 * @param err Error code if an error occurs
 * @param err_info Error information if an error occurs
 * @return WTAP_OPEN_ERROR on failure, otherwise a value indicating success or not being the correct file type
 */
wtap_open_return_val netlog_open(wtap *wth, int *err, char **err_info);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
