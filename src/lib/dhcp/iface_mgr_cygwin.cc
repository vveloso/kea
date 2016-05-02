// Copyright (C) 2011-2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// @file
/// Access to interface information on Linux is via netlink, a socket-based
/// method for transferring information between the kernel and user processes.
///
/// For detailed information about netlink interface, please refer to
/// http://en.wikipedia.org/wiki/Netlink and RFC3549.  Comments in the
/// detectIfaces() method (towards the end of this file) provide an overview
/// on how the netlink interface is used here.
///
/// Note that this interface is very robust and allows many operations:
/// add/get/set/delete links, addresses, routes, queuing, manipulation of
/// traffic classes, manipulation of neighbourhood tables and even the ability
/// to do something with address labels. Getting a list of interfaces with
/// addresses configured on it is just a small subset of all possible actions.

#include <config.h>

#if defined(__CYGWIN__)

#include <asiolink/io_address.h>
#include <dhcp/iface_mgr.h>
#include <dhcp/iface_mgr_error_handler.h>
#include <dhcp/pkt_filter_inet.h>
#include <exceptions/exceptions.h>
#include <log/logger.h>
#include <log/macros.h>

#include <boost/foreach.hpp>

#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

using namespace std;
using namespace isc;
using namespace isc::asiolink;
using namespace isc::dhcp;

/// @brief Logger used by the cygwin IfaceMgr port.
isc::log::Logger logger("IfaceMgr");

namespace isc {
namespace dhcp {

void
processDetectedInterface(const ifaddrs *ifa, IfaceMgr::IfaceCollection& ifaces) {
	if (NULL == ifa->ifa_addr) {
		return;
	}

	int index = if_nametoindex(ifa->ifa_name);
	if (index < 0) {
		LOG_ERROR(logger, "Failed to determine index of interface %1").arg(ifa->ifa_name);
		return;
	}
	
	int family = ifa->ifa_addr->sa_family;
	if (AF_INET != family && AF_INET6 != family) {
		LOG_INFO(logger, "Unsupported interface %1/%2 with address family %3").arg(ifa->ifa_name).arg(index).arg(family);
		return;
	}

	IOAddress address = IOAddress::fromBytes(family, 
		family == AF_INET ? (const uint8_t*) &((sockaddr_in*) ifa->ifa_addr)->sin_addr : (const uint8_t*) &((sockaddr_in6*) ifa->ifa_addr)->sin6_addr);
	string address_str = address.toText();

	BOOST_FOREACH(IfacePtr iface, ifaces) {
		if (iface->getName().compare(ifa->ifa_name) == 0) {
			iface->addAddress(address);
			LOG_INFO(logger, "Updated interface %1 with address %2").arg(iface->getFullName()).arg(address);
			return;
		}
	}

	IfacePtr iface(new Iface(ifa->ifa_name, index));
	iface->setFlags(ifa->ifa_flags);
	iface->setHWType(HWTYPE_ETHERNET);
	iface->addAddress(address);
	ifaces.push_back(iface);
	LOG_INFO(logger, "Discovered interface %1 with address %2").arg(iface->getFullName()).arg(address);
}

void
IfaceMgr::detectIfaces() {
	ifaddrs *ifs;
	
	if (getifaddrs(&ifs) < 0) {
		isc_throw(IfaceDetectError,
			  "Interface detection could not start.");
	}
	
	for (const ifaddrs *ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {
		processDetectedInterface(ifa, ifaces_);
	}
	
	freeifaddrs(ifs);
}

void
IfaceMgr::setMatchingPacketFilter(const bool direct_response_desired __attribute__((unused))) {
	setPacketFilter(PktFilterPtr(new PktFilterInet()));
}

} // end of isc::dhcp namespace
} // end of isc namespace

#endif // if defined(__CYGWIN__)
