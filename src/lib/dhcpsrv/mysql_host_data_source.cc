// Copyright (C) 2015-2016 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <config.h>

#include <dhcpsrv/dhcpsrv_log.h>
#include <dhcpsrv/mysql_host_data_source.h>
#include <dhcpsrv/db_exceptions.h>

#include <boost/pointer_cast.hpp>
#include <boost/static_assert.hpp>

#include <mysql.h>
#include <mysqld_error.h>

#include <stdint.h>
#include <string>

using namespace isc;
using namespace isc::dhcp;
using namespace isc::asiolink;
using namespace std;

namespace {

/// @brief Maximum size of an IPv6 address represented as a text string.
///
/// This is 32 hexadecimal characters written in 8 groups of four, plus seven
/// colon separators.
const size_t ADDRESS6_TEXT_MAX_LEN = 39;

/// @brief Maximum length of classes stored in a dhcp4/6_client_classes
/// columns.
const size_t CLIENT_CLASSES_MAX_LEN = 255;

/// @brief Maximum length of the hostname stored in DNS.
///
/// This length is restricted by the length of the domain-name carried
/// in the Client FQDN %Option (see RFC4702 and RFC4704).
const size_t HOSTNAME_MAX_LEN = 255;

/// @brief Numeric value representing last supported identifier.
///
/// This value is used to validate whether the identifier type stored in
/// a database is within bounds. of supported identifiers.
const uint8_t MAX_IDENTIFIER_TYPE = static_cast<uint8_t>(Host::IDENT_CIRCUIT_ID);

/// @brief Prepared MySQL statements used by the backend to insert and
/// retrieve hosts from the database.
TaggedStatement tagged_statements[] = {
    // Inserts a host into the 'hosts' table.
    {MySqlHostDataSource::INSERT_HOST,
         "INSERT INTO hosts(host_id, dhcp_identifier, dhcp_identifier_type, "
            "dhcp4_subnet_id, dhcp6_subnet_id, ipv4_address, hostname, "
            "dhcp4_client_classes, dhcp6_client_classes) "
         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"},

    // Inserts a single IPv6 reservation into 'reservations' table.
    {MySqlHostDataSource::INSERT_V6_RESRV,
         "INSERT INTO ipv6_reservations(address, prefix_len, type, "
            "dhcp6_iaid, host_id) "
         "VALUES (?,?,?,?,?)"},

    // Retrieves host information along with IPv6 reservations associated
    // with this host. If the host exists in multiple subnets, all hosts
    // having a specified identifier will be returned from those subnets.
    // Because LEFT JOIN clause is used, the number of rows returned for
    // a single host depends on the number of reservations.
    {MySqlHostDataSource::GET_HOST_DHCPID,
            "SELECT h.host_id, h.dhcp_identifier, h.dhcp_identifier_type, "
                "h.dhcp4_subnet_id, h.dhcp6_subnet_id, h.ipv4_address, "
                "h.hostname, h.dhcp4_client_classes, h.dhcp6_client_classes, "
                "r.address, r.prefix_len, r.type, r.dhcp6_iaid "
            "FROM hosts AS h "
            "LEFT JOIN ipv6_reservations AS r "
                "ON h.host_id = r.host_id "
            "WHERE dhcp_identifier = ? AND dhcp_identifier_type = ?"},

    // Retrieves host information by IPv4 address. This should typically
    // return a single host, but if we ever allow for defining subnets
    // with overlapping address pools, multiple hosts may be returned.
    {MySqlHostDataSource::GET_HOST_ADDR,
            "SELECT host_id, dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, dhcp6_subnet_id, ipv4_address, hostname, "
                "dhcp4_client_classes, dhcp6_client_classes "
            "FROM hosts "
            "WHERE ipv4_address = ?"},

    // Retrieves host information by subnet identifier and unique
    // identifier of a client. This is expected to return a single host.
    {MySqlHostDataSource::GET_HOST_SUBID4_DHCPID,
            "SELECT host_id, dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, dhcp6_subnet_id, ipv4_address, hostname, "
                "dhcp4_client_classes, dhcp6_client_classes "
            "FROM hosts "
            "WHERE dhcp4_subnet_id = ? AND dhcp_identifier_type = ? "
            "   AND dhcp_identifier = ?"},

    // Retrieves host information by subnet identifier and unique
    // identifier of a client. This query should return information
    // for a single host but multiple rows are returned due to
    // use of LEFT JOIN clause. The number of rows returned for a single
    // host dpeneds on the number of IPv6 reservations existing for
    // this client.
    {MySqlHostDataSource::GET_HOST_SUBID6_DHCPID,
            "SELECT DISTINCT h.host_id, h.dhcp_identifier, "
                "h.dhcp_identifier_type, h.dhcp4_subnet_id, "
                "h.dhcp6_subnet_id, h.ipv4_address, h.hostname, "
                "h.dhcp4_client_classes, h.dhcp6_client_classes, "
                "r.address, r.prefix_len, r.type, r.dhcp6_iaid "
            "FROM hosts AS h "
            "LEFT JOIN ipv6_reservations AS r "
                "ON h.host_id = r.host_id "
            "WHERE dhcp6_subnet_id = ? AND dhcp_identifier_type = ? "
                "AND dhcp_identifier = ? "
            "ORDER BY h.host_id, r.prefix_len, r.address"},

    // Retrieves host information using subnet identifier and the
    // IPv4 address reservation. This should return inforamation for
    // a single host.
    {MySqlHostDataSource::GET_HOST_SUBID_ADDR,
            "SELECT host_id, dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, dhcp6_subnet_id, ipv4_address, hostname, "
                "dhcp4_client_classes, dhcp6_client_classes "
            "FROM hosts "
            "WHERE dhcp4_subnet_id = ? AND ipv4_address = ?"},

    // Retrieves host information using IPv6 prefix and prefix length
    // or IPv6 address. This query returns host information for a
    // single host. However, multiple rows are returned by this
    // query due to use of LEFT JOIN clause with 'ipv6_reservations'
    // table. The number of rows returned depends on the number of
    // reservations for a particular host.
    {MySqlHostDataSource::GET_HOST_PREFIX,
            "SELECT DISTINCT h.host_id, h.dhcp_identifier, "
                "h.dhcp_identifier_type, h.dhcp4_subnet_id, "
                "h.dhcp6_subnet_id, h.ipv4_address, h.hostname, "
                "h.dhcp4_client_classes, h.dhcp6_client_classes, "
                "r.address, r.prefix_len, r.type, r.dhcp6_iaid "
            "FROM hosts AS h "
            "LEFT JOIN ipv6_reservations AS r "
                "ON h.host_id = r.host_id "
            "WHERE h.host_id = "
                "(SELECT host_id FROM ipv6_reservations "
                 "WHERE address = ? AND prefix_len = ?) "
            "ORDER BY h.host_id, r.prefix_len, r.address"},

    // Retrieves MySQL schema version.
    {MySqlHostDataSource::GET_VERSION,
            "SELECT version, minor FROM schema_version"},

    // Marks the end of the statements table.
    {MySqlHostDataSource::NUM_STATEMENTS, NULL}
};

/// @brief This class provides mechanisms for sending and retrieving
/// information from the 'hosts' table.
///
/// This class should be used to create new entries in the 'hosts'
/// table and to retrieve DHCPv4 reservations from this table. The
/// queries used with this class do not retrieve IPv6 reservations for
/// the hosts to minimize negative impact on performance.
///
/// The derived class MySqlHostIPv6Exchange extends this class to facilitate
/// retrieving IPv6 reservations along with the host information.
class MySqlHostExchange {
private:

    /// @brief Number of columns returned for queries used with this class.
    static const size_t HOST_COLUMNS = 9;

public:

    /// @brief Constructor
    ///
    /// The initialization of the variables here is only to satisfy cppcheck -
    /// all variables are initialized/set in the methods before they are used.
    MySqlHostExchange()
        : bind_(HOST_COLUMNS), columns_(HOST_COLUMNS),
          error_(HOST_COLUMNS, MLM_FALSE), host_id_(0),
          dhcp_identifier_length_(0), dhcp_identifier_type_(0),
          dhcp4_subnet_id_(0), dhcp6_subnet_id_(0), ipv4_address_(0),
          hostname_length_(0), dhcp4_client_classes_length_(0),
          dhcp6_client_classes_length_(0), dhcp4_subnet_id_null_(MLM_FALSE),
          dhcp6_subnet_id_null_(MLM_FALSE), ipv4_address_null_(MLM_FALSE),
          hostname_null_(MLM_FALSE), dhcp4_client_classes_null_(MLM_FALSE),
          dhcp6_client_classes_null_(MLM_FALSE) {

        // Fill arrays with 0 so as they don't include any garbage.
        memset(dhcp_identifier_buffer_, 0, sizeof(dhcp_identifier_buffer_));
        memset(hostname_, 0, sizeof(hostname_));
        memset(dhcp4_client_classes_, 0, sizeof(dhcp4_client_classes_));
        memset(dhcp6_client_classes_, 0, sizeof(dhcp6_client_classes_));

        // Set the column names (for error messages)
        columns_[0] = "host_id";
        columns_[1] = "dhcp_identifier";
        columns_[2] = "dhcp_identifier_type";
        columns_[3] = "dhcp4_subnet_id";
        columns_[4] = "dhcp6_subnet_id";
        columns_[5] = "ipv4_address";
        columns_[6] = "hostname";
        columns_[7] = "dhcp4_client_classes";
        columns_[8] = "dhcp6_client_classes";

        BOOST_STATIC_ASSERT(8 < HOST_COLUMNS);
    };

    /// @brief Virtual destructor.
    virtual ~MySqlHostExchange() {
    }

    /// @brief Returns value of host id.
    ///
    /// This method is used by derived classes.
    uint64_t getHostId() const {
        return (host_id_);
    };

    /// @brief Set error indicators
    ///
    /// Sets the error indicator for each of the MYSQL_BIND elements. It points
    /// the "error" field within an element of the input array to the
    /// corresponding element of the passed error array.
    ///
    /// @param bind Array of BIND elements
    /// @param error Array of error elements.  If there is an error in getting
    ///        data associated with one of the "bind" elements, the
    ///        corresponding element in the error array is set to MLM_TRUE.
    static void setErrorIndicators(std::vector<MYSQL_BIND>& bind,
                                   std::vector<my_bool>& error) {
        for (size_t i = 0; i < error.size(); ++i) {
            error[i] = MLM_FALSE;
            bind[i].error = reinterpret_cast<char*>(&error[i]);
        }
    };

    /// @brief Return columns in error
    ///
    /// If an error is returned from a fetch (in particular, a truncated
    /// status), this method can be called to get the names of the fields in
    /// error.  It returns a string comprising the names of the fields
    /// separated by commas.  In the case of there being no error indicators
    /// set, it returns the string "(None)".
    ///
    /// @param error Array of error elements.  An element is set to MLM_TRUE
    ///        if the corresponding column in the database is the source of
    ///        the error.
    /// @param names Array of column names, the same size as the error array.
    /// @param count Size of each of the arrays.
    static std::string getColumnsInError(std::vector<my_bool>& error,
                                         const std::vector<std::string>& names) {
        std::string result = "";

        // Accumulate list of column names
        for (size_t i = 0; i < names.size(); ++i) {
            if (error[i] == MLM_TRUE) {
                if (!result.empty()) {
                    result += ", ";
                }
                result += names[i];
            }
        }

        if (result.empty()) {
            result = "(None)";
        }

        return (result);
    };

    /// @brief Create MYSQL_BIND objects for Host Pointer
    ///
    /// Fills in the MYSQL_BIND array for sending data stored in the Host object
    /// to the database.
    ///
    /// @param host Host object to be added to the database.
    ///        None of the fields in the host reservation are modified -
    ///        the host data is only read.
    ///
    /// @return Vector of MySQL BIND objects representing the data to be added.
    std::vector<MYSQL_BIND> createBindForSend(const HostPtr& host) {
        // Store host object to ensure it remains valid.
        host_ = host;

        // Initialize prior to constructing the array of MYSQL_BIND structures.
        // It sets all fields, including is_null, to zero, so we need to set
        // is_null only if it should be true. This gives up minor performance
        // benefit while being safe approach.
        memset(&bind_[0], 0, sizeof(MYSQL_BIND) * bind_.size());

        // Set up the structures for the various components of the host structure.

        try {
            // host_id : INT UNSIGNED NOT NULL
            // The host_id is auto_incremented by MySQL database,
            // so we need to pass the NULL value
            host_id_ = static_cast<uint32_t>(NULL);
            bind_[0].buffer_type = MYSQL_TYPE_LONG;
            bind_[0].buffer = reinterpret_cast<char*>(&host_id_);
            bind_[0].is_unsigned = MLM_TRUE;

            // dhcp_identifier : VARBINARY(128) NOT NULL
            dhcp_identifier_length_ = host->getIdentifier().size();
            memcpy(static_cast<void*>(dhcp_identifier_buffer_),
                   &(host->getIdentifier())[0],
                   host->getIdentifier().size());

            bind_[1].buffer_type = MYSQL_TYPE_BLOB;
            bind_[1].buffer = dhcp_identifier_buffer_;
            bind_[1].buffer_length = dhcp_identifier_length_;
            bind_[1].length = &dhcp_identifier_length_;

            // dhcp_identifier_type : TINYINT NOT NULL
            dhcp_identifier_type_ = static_cast<uint8_t>(host->getIdentifierType());
            bind_[2].buffer_type = MYSQL_TYPE_TINY;
            bind_[2].buffer = reinterpret_cast<char*>(&dhcp_identifier_type_);
            bind_[2].is_unsigned = MLM_TRUE;

            // dhcp4_subnet_id : INT UNSIGNED NULL
            // Can't take an address of intermediate object, so let's store it
            // in dhcp4_subnet_id_
            dhcp4_subnet_id_ = host->getIPv4SubnetID();
            bind_[3].buffer_type = MYSQL_TYPE_LONG;
            bind_[3].buffer = reinterpret_cast<char*>(&dhcp4_subnet_id_);
            bind_[3].is_unsigned = MLM_TRUE;

            // dhcp6_subnet_id : INT UNSIGNED NULL
            // Can't take an address of intermediate object, so let's store it
            // in dhcp6_subnet_id_
            dhcp6_subnet_id_ = host->getIPv6SubnetID();
            bind_[4].buffer_type = MYSQL_TYPE_LONG;
            bind_[4].buffer = reinterpret_cast<char*>(&dhcp6_subnet_id_);
            bind_[4].is_unsigned = MLM_TRUE;

            // ipv4_address : INT UNSIGNED NULL
            // The address in the Host structure is an IOAddress object.  Convert
            // this to an integer for storage.
            ipv4_address_ = static_cast<uint32_t>(host->getIPv4Reservation());
            bind_[5].buffer_type = MYSQL_TYPE_LONG;
            bind_[5].buffer = reinterpret_cast<char*>(&ipv4_address_);
            bind_[5].is_unsigned = MLM_TRUE;
            // bind_[5].is_null = &MLM_FALSE; // commented out for performance
                                                      // reasons, see memset() above

            // hostname : VARCHAR(255) NULL
            strncpy(hostname_, host->getHostname().c_str(), HOSTNAME_MAX_LEN - 1);
            hostname_length_ = host->getHostname().length();
            bind_[6].buffer_type = MYSQL_TYPE_STRING;
            bind_[6].buffer = reinterpret_cast<char*>(hostname_);
            bind_[6].buffer_length = hostname_length_;

            // dhcp4_client_classes : VARCHAR(255) NULL
            bind_[7].buffer_type = MYSQL_TYPE_STRING;
            // Override default separator to not include space after comma.
            string classes4_txt = host->getClientClasses4().toText(",");
            strncpy(dhcp4_client_classes_, classes4_txt.c_str(), CLIENT_CLASSES_MAX_LEN - 1);
            bind_[7].buffer = dhcp4_client_classes_;
            bind_[7].buffer_length = classes4_txt.length();

            // dhcp6_client_classes : VARCHAR(255) NULL
            bind_[8].buffer_type = MYSQL_TYPE_STRING;
            // Override default separator to not include space after comma.
            string classes6_txt = host->getClientClasses6().toText(",");
            strncpy(dhcp6_client_classes_, classes6_txt.c_str(), CLIENT_CLASSES_MAX_LEN - 1);
            bind_[8].buffer = dhcp6_client_classes_;
            bind_[8].buffer_length = classes6_txt.length();
            bind_[8].buffer_length = sizeof(host->getClientClasses6());

        } catch (const std::exception& ex) {
            isc_throw(DbOperationError,
                      "Could not create bind array from Host: "
                      << host->getHostname() << ", reason: " << ex.what());
        }

        // Add the data to the vector.  Note the end element is one after the
        // end of the array.
        return (std::vector<MYSQL_BIND>(&bind_[0], &bind_[HOST_COLUMNS]));
    };

    /// @brief Create BIND array to receive Host data.
    ///
    /// Creates a MYSQL_BIND array to receive Host data from the database.
    /// After data is successfully received, @ref retrieveHost can be called
    /// to retrieve the Host object.
    ///
    /// @return Vector of MYSQL_BIND objects representing data to be retrieved.
    virtual std::vector<MYSQL_BIND> createBindForReceive() {
        // Initialize MYSQL_BIND array.
        // It sets all fields, including is_null, to zero, so we need to set
        // is_null only if it should be true. This gives up minor performance
        // benefit while being safe approach. For improved readability, the
        // code that explicitly sets is_null is there, but is commented out.
        // This also takes care of seeeting bind_[X].is_null to MLM_FALSE.
        memset(&bind_[0], 0, sizeof(MYSQL_BIND) * bind_.size());

        // host_id : INT UNSIGNED NOT NULL
        bind_[0].buffer_type = MYSQL_TYPE_LONG;
        bind_[0].buffer = reinterpret_cast<char*>(&host_id_);
        bind_[0].is_unsigned = MLM_TRUE;

        // dhcp_identifier : VARBINARY(128) NOT NULL
        dhcp_identifier_length_ = sizeof(dhcp_identifier_buffer_);
        bind_[1].buffer_type = MYSQL_TYPE_BLOB;
        bind_[1].buffer = reinterpret_cast<char*>(dhcp_identifier_buffer_);
        bind_[1].buffer_length = dhcp_identifier_length_;
        bind_[1].length = &dhcp_identifier_length_;

        // dhcp_identifier_type : TINYINT NOT NULL
        bind_[2].buffer_type = MYSQL_TYPE_TINY;
        bind_[2].buffer = reinterpret_cast<char*>(&dhcp_identifier_type_);
        bind_[2].is_unsigned = MLM_TRUE;

        // dhcp4_subnet_id : INT UNSIGNED NULL
        dhcp4_subnet_id_null_ = MLM_FALSE;
        bind_[3].buffer_type = MYSQL_TYPE_LONG;
        bind_[3].buffer = reinterpret_cast<char*>(&dhcp4_subnet_id_);
        bind_[3].is_unsigned = MLM_TRUE;
        bind_[3].is_null = &dhcp4_subnet_id_null_;

        // dhcp6_subnet_id : INT UNSIGNED NULL
        dhcp6_subnet_id_null_ = MLM_FALSE;
        bind_[4].buffer_type = MYSQL_TYPE_LONG;
        bind_[4].buffer = reinterpret_cast<char*>(&dhcp6_subnet_id_);
        bind_[4].is_unsigned = MLM_TRUE;
        bind_[4].is_null = &dhcp6_subnet_id_null_;

        // ipv4_address : INT UNSIGNED NULL
        ipv4_address_null_ = MLM_FALSE;
        bind_[5].buffer_type = MYSQL_TYPE_LONG;
        bind_[5].buffer = reinterpret_cast<char*>(&ipv4_address_);
        bind_[5].is_unsigned = MLM_TRUE;
        bind_[5].is_null = &ipv4_address_null_;

        // hostname : VARCHAR(255) NULL
        hostname_null_ = MLM_FALSE;
        hostname_length_ = sizeof(hostname_);
        bind_[6].buffer_type = MYSQL_TYPE_STRING;
        bind_[6].buffer = reinterpret_cast<char*>(hostname_);
        bind_[6].buffer_length = hostname_length_;
        bind_[6].length = &hostname_length_;
        bind_[6].is_null = &hostname_null_;

        // dhcp4_client_classes : VARCHAR(255) NULL
        dhcp4_client_classes_null_ = MLM_FALSE;
        dhcp4_client_classes_length_ = sizeof(dhcp4_client_classes_);
        bind_[7].buffer_type = MYSQL_TYPE_STRING;
        bind_[7].buffer = reinterpret_cast<char*>(dhcp4_client_classes_);
        bind_[7].buffer_length = dhcp4_client_classes_length_;
        bind_[7].length = &dhcp4_client_classes_length_;
        bind_[7].is_null = &dhcp4_client_classes_null_;

        // dhcp6_client_classes : VARCHAR(255) NULL
        dhcp6_client_classes_null_ = MLM_FALSE;
        dhcp6_client_classes_length_ = sizeof(dhcp6_client_classes_);
        bind_[8].buffer_type = MYSQL_TYPE_STRING;
        bind_[8].buffer = reinterpret_cast<char*>(dhcp6_client_classes_);
        bind_[8].buffer_length = dhcp6_client_classes_length_;
        bind_[8].length = &dhcp6_client_classes_length_;
        bind_[8].is_null = &dhcp6_client_classes_null_;

        // Add the error flags
        setErrorIndicators(bind_, error_);

        // Add the data to the vector.  Note the end element is one after the
        // end of the array.
        return (bind_);
    };

    /// @brief Copy received data into Host object
    ///
    /// This function copies information about the host into a newly created
    /// @ref Host object. This method is called after @ref createBindForReceive.
    /// has been used.
    ///
    /// @return Host Pointer to a @ref HostPtr object holding a pointer to the
    /// @ref Host object returned.
    HostPtr retrieveHost() {
        // Check if the identifier stored in the database is correct.
        if (dhcp_identifier_type_ > MAX_IDENTIFIER_TYPE) {
            isc_throw(BadValue, "invalid dhcp identifier type returned: "
                      << static_cast<int>(dhcp_identifier_type_));
        }
        // Set the dhcp identifier type in a variable of the appropriate data type.
        Host::IdentifierType type =
            static_cast<Host::IdentifierType>(dhcp_identifier_type_);

        // Set DHCPv4 subnet ID to the value returned. If NULL returned, set to 0.
        SubnetID ipv4_subnet_id(0);
        if (dhcp4_subnet_id_null_ == MLM_FALSE) {
            ipv4_subnet_id = static_cast<SubnetID>(dhcp4_subnet_id_);
        }

        // Set DHCPv6 subnet ID to the value returned. If NULL returned, set to 0.
        SubnetID ipv6_subnet_id(0);
        if (dhcp6_subnet_id_null_ == MLM_FALSE) {
            ipv6_subnet_id = static_cast<SubnetID>(dhcp6_subnet_id_);
        }

        // Set IPv4 address reservation if it was given, if not, set IPv4 zero address
        asiolink::IOAddress ipv4_reservation = asiolink::IOAddress::IPV4_ZERO_ADDRESS();
        if (ipv4_address_null_ == MLM_FALSE) {
            ipv4_reservation = asiolink::IOAddress(ipv4_address_);
        }

        // Set hostname if non NULL value returned. Otherwise, leave an empty string.
        std::string hostname;
        if (hostname_null_ == MLM_FALSE) {
            hostname = std::string(hostname_, hostname_length_);
        }

        // Set DHCPv4 client classes if non NULL value returned.
        std::string dhcp4_client_classes;
        if (dhcp4_client_classes_null_ == MLM_FALSE) {
            dhcp4_client_classes = std::string(dhcp4_client_classes_,
                                               dhcp4_client_classes_length_);
        }

        // Set DHCPv6 client classes if non NULL value returned.
        std::string dhcp6_client_classes;
        if (dhcp6_client_classes_null_ == MLM_FALSE) {
            dhcp6_client_classes = std::string(dhcp6_client_classes_,
                                               dhcp6_client_classes_length_);
        }

        // Create and return Host object from the data gathered.
        HostPtr h(new Host(dhcp_identifier_buffer_, dhcp_identifier_length_,
                           type, ipv4_subnet_id, ipv6_subnet_id, ipv4_reservation,
                           hostname, dhcp4_client_classes, dhcp6_client_classes));
        h->setHostId(host_id_);

        return (h);
    };

    /// @brief Processes one row of data fetched from a database.
    ///
    /// The processed data must contain host id, which uniquely identifies a
    /// host. This method creates a host and inserts it to the hosts collection
    /// only if the last inserted host has a different host id. This prevents
    /// adding duplicated hosts to the collection, assuming that processed
    /// rows are primarily ordered by host id column.
    ///
    /// @todo This method will need to be extended to process options
    /// associated with hosts.
    ///
    /// @param [out] hosts Collection of hosts to which a new host created
    ///        from the processed data should be inserted.
    virtual void processFetchedData(ConstHostCollection& hosts) {
        HostPtr host;
        // Add new host only if there are no hosts yet or the host id of the
        // most recently added host is different than the host id of the
        // currently processed host.
        if (hosts.empty() || (hosts.back()->getHostId() != getHostId())) {
            // Create Host object from the fetched data and append it to the
            // collection.
            host = retrieveHost();
            hosts.push_back(host);
        }
    }

    /// @brief Return columns in error
    ///
    /// If an error is returned from a fetch (in particular, a truncated
    /// status), this method can be called to get the names of the fields in
    /// error.  It returns a string comprising the names of the fields
    /// separated by commas.  In the case of there being no error indicators
    /// set, it returns the string "(None)".
    ///
    /// @return Comma-separated list of columns in error, or the string
    ///         "(None)".
    std::string getErrorColumns() {
        return (getColumnsInError(error_, columns_));
    };

protected:

    /// Vector of MySQL bindings.
    std::vector<MYSQL_BIND> bind_;

    /// Column names.
    std::vector<std::string> columns_;

    /// Error array.
    std::vector<my_bool> error_;

    /// Pointer to Host object holding information to be inserted into
    /// Hosts table.
    HostPtr host_;

private:

    /// Host identifier (primary key in Hosts table).
    uint64_t host_id_;

    /// Buffer holding client's identifier (e.g. DUID, HW address)
    /// in the binary format.
    uint8_t dhcp_identifier_buffer_[DUID::MAX_DUID_LEN];

    /// Length of a data in the dhcp_identifier_buffer_.
    size_t dhcp_identifier_length_;

    /// Type of the identifier in the dhcp_identifier_buffer_. This
    /// value corresponds to the @ref Host::IdentifierType value.
    uint8_t dhcp_identifier_type_;

    /// DHCPv4 subnet identifier.
    uint32_t dhcp4_subnet_id_;

    /// DHCPv6 subnet identifier.
    uint32_t dhcp6_subnet_id_;

    /// Reserved IPv4 address.
    uint32_t ipv4_address_;

    /// Name reserved for the host.
    char hostname_[HOSTNAME_MAX_LEN];

    /// Hostname length.
    unsigned long hostname_length_;

    /// A string holding comma separated list of DHCPv4 client classes.
    char dhcp4_client_classes_[CLIENT_CLASSES_MAX_LEN];

    /// A length of the string holding comma separated list of DHCPv4
    /// client classes.
    unsigned long dhcp4_client_classes_length_;

    /// A string holding comma separated list of DHCPv6 client classes.
    char dhcp6_client_classes_[CLIENT_CLASSES_MAX_LEN];

    /// A length of the string holding comma separated list of DHCPv6
    /// client classes.
    unsigned long dhcp6_client_classes_length_;

    /// @name Boolean values indicating if values of specific columns in
    /// the database are NULL.
    //@{
    /// Boolean flag indicating if the value of the DHCPv4 subnet is NULL.
    my_bool dhcp4_subnet_id_null_;

    /// Boolean flag indicating if the value of the DHCPv6 subnet is NULL.
    my_bool dhcp6_subnet_id_null_;

    /// Boolean flag indicating if the value of IPv4 reservation is NULL.
    my_bool ipv4_address_null_;

    /// Boolean flag indicating if the value if hostname is NULL.
    my_bool hostname_null_;

    /// Boolean flag indicating if the value of DHCPv4 client classes is
    /// NULL.
    my_bool dhcp4_client_classes_null_;

    /// Boolean flag indicating if the value of DHCPv6 client classes is
    /// NULL.
    my_bool dhcp6_client_classes_null_;

    //@}

};

/// @brief This class provides mechanisms for sending and retrieving
/// host information and associated IPv6 reservations.
///
/// This class extends the @ref MySqlHostExchange class with the
/// mechanisms to retrieve IPv6 reservations along with host
/// information. It is assumed that both host data and IPv6
/// reservations are retrieved with a single query (using LEFT JOIN
/// MySQL clause). Because the host to IPv6 reservation is a 1-to-many
/// relation, the same row from the Host table is returned many times
/// (for each IPv6 reservation). This class is responsible for
/// converting those multiple host instances into a single Host
/// object with multiple IPv6 reservations.
class MySqlHostIPv6Exchange : public MySqlHostExchange {
private:

    /// @brief Number of columns returned in the queries used by
    /// @ref MySqlHostIPv6Exchange.
    static const size_t RESERVATION_COLUMNS = 13;

public:

    /// @brief Constructor.
    ///
    /// Apart from initializing the base class data structures it also
    /// initializes values representing IPv6 reservation information.
    MySqlHostIPv6Exchange()
        : MySqlHostExchange(), reserv_type_(0), reserv_type_null_(MLM_FALSE),
          ipv6_address_buffer_len_(0), prefix_len_(0), iaid_(0) {

        memset(ipv6_address_buffer_, 0, sizeof(ipv6_address_buffer_));

        // Append additional columns returned by the queries.
        columns_.push_back("address");
        columns_.push_back("prefix_len");
        columns_.push_back("type");
        columns_.push_back("dhcp6_iaid");

        // Resize binding table initialized in the base class. Do not
        // run memset on this table, because it is when createBindForReceive
        // is called.
        bind_.resize(RESERVATION_COLUMNS);

        // Resize error table.
        error_.resize(RESERVATION_COLUMNS);
        std::fill(&error_[0], &error_[RESERVATION_COLUMNS], MLM_FALSE);
    }

    /// @brief Checks if a currently processed row contains IPv6 reservation.
    ///
    /// @return true if IPv6 reservation data is non-null for the processed
    /// row, false otherwise.
    bool hasReservation() const {
        return (reserv_type_null_ == MLM_FALSE);
    };

    /// @brief Create IPv6 reservation from the data contained in the
    /// currently processed row.
    ///
    /// Called after the MYSQL_BIND array created by createBindForReceive().
    ///
    /// @return IPv6Resrv object (containing IPv6 address or prefix reservation)
    IPv6Resrv retrieveReservation() {
        // Set the IPv6 Reservation type (0 = IA_NA, 2 = IA_PD)
        IPv6Resrv::Type type = IPv6Resrv::TYPE_NA;

        switch (reserv_type_) {
        case 0:
            type = IPv6Resrv::TYPE_NA;
            break;

        case 2:
            type = IPv6Resrv::TYPE_PD;
            break;

        default:
            isc_throw(BadValue,
                      "invalid IPv6 reservation type returned: "
                      << static_cast<int>(reserv_type_)
                      << ". Only 0 or 2 are allowed.");
        }

        ipv6_address_buffer_[ipv6_address_buffer_len_] = '\0';
        std::string address = ipv6_address_buffer_;
        IPv6Resrv r(type, IOAddress(address), prefix_len_);
        return (r);
    };

    /// @brief Processes one row of data fetched from a database.
    ///
    /// The processed data must contain host id, which uniquely identifies a
    /// host. This method creates a host and inserts it to the hosts collection
    /// only if the last inserted host has a different host id. This prevents
    /// adding duplicated hosts to the collection, assuming that processed
    /// rows are primarily ordered by host id column.
    ///
    /// For any returned row which contains IPv6 reservation information it
    /// creates a @ref IPv6Resrv and appends it to the collection of the
    /// IPv6 reservations in a Host object.
    ///
    /// @todo This method will need to be extended to process DHCPv6 options
    /// associated with hosts.
    ///
    /// @param [out] hosts Collection of hosts to which a new host created
    ///        from the processed data should be inserted.
    virtual void processFetchedData(ConstHostCollection& hosts) {
        HostPtr host;
        HostPtr most_recent_host;

        // If there are any hosts already created, let's obtain an instance
        // to the most recently added host. We will have to check if the
        // currently processed row contains some data for this host or a
        // different host. In the former case, we'll need to update the
        // host information.
        if (!hosts.empty()) {
            // Const cast is not very elegant way to deal with it, but
            // there is a good reason to use it here. This method is called
            // to build a collection of const hosts to be returned to the
            // caller. If we wanted to use non-const collection we'd need
            // to copy the whole collection before returning it, which has
            // performance implications. Alternatively, we could store the
            // most recently added host in a class member but this would
            // make the code less readable.
            most_recent_host = boost::const_pointer_cast<Host>(hosts.back());
        }

        // If there is no existing host or the new host id doesn't match
        // we need to create a new host.
        if (!most_recent_host || (most_recent_host->getHostId() != getHostId())) {
            host = retrieveHost();
            // If the row also contains IPv6 reservation we should add it
            // to the host.
            if (hasReservation()) {
                host->addReservation(retrieveReservation());
            }
            // In any case let's put the new host in the results.
            hosts.push_back(host);

        // If the returned row pertains to an existing host, let's just
        // add a reservation.
        } else if (hasReservation() && most_recent_host) {
            most_recent_host->addReservation(retrieveReservation());
        }
    }

    /// @brief Create BIND array to receive Host data with IPv6 reservations.
    ///
    /// Creates a MYSQL_BIND array to receive Host data from the database.
    /// After data is successfully received, @ref processedFetchedData is
    /// called for each returned row to build collection of @ref Host
    /// objects with associated IPv6 reservations.
    ///
    /// @return Vector of MYSQL_BIND objects representing data to be retrieved.
    virtual std::vector<MYSQL_BIND> createBindForReceive() {
        // The following call sets bind_ values between 0 and 8.
        static_cast<void>(MySqlHostExchange::createBindForReceive());

        // IPv6 address/prefix VARCHAR(39)
        ipv6_address_buffer_len_ = sizeof(ipv6_address_buffer_) - 1;
        bind_[9].buffer_type = MYSQL_TYPE_STRING;
        bind_[9].buffer = ipv6_address_buffer_;
        bind_[9].buffer_length = ipv6_address_buffer_len_;
        bind_[9].length = &ipv6_address_buffer_len_;

        // prefix_len : TINYINT
        bind_[10].buffer_type = MYSQL_TYPE_TINY;
        bind_[10].buffer = reinterpret_cast<char*>(&prefix_len_);
        bind_[10].is_unsigned = MLM_TRUE;

        // (reservation) type : TINYINT
        reserv_type_null_ = MLM_FALSE;
        bind_[11].buffer_type = MYSQL_TYPE_TINY;
        bind_[11].buffer = reinterpret_cast<char*>(&reserv_type_);
        bind_[11].is_unsigned = MLM_TRUE;
        bind_[11].is_null = &reserv_type_null_;

        // dhcp6_iaid INT UNSIGNED
        bind_[12].buffer_type = MYSQL_TYPE_LONG;
        bind_[12].buffer = reinterpret_cast<char*>(&iaid_);
        bind_[12].is_unsigned = MLM_TRUE;

        // Add the error flags
        setErrorIndicators(bind_, error_);

        // Add the data to the vector.  Note the end element is one after the
        // end of the array.
        return (bind_);
    };

private:

    /// @brief IPv6 reservation type.
    uint8_t reserv_type_;

    /// @brief Boolean flag indicating if reservation type field is null.
    ///
    /// This flag is used by the class to determine if the returned row
    /// contains IPv6 reservation information.
    my_bool reserv_type_null_;

    /// @brief Buffer holding IPv6 address/prefix in textual format.
    char ipv6_address_buffer_[ADDRESS6_TEXT_MAX_LEN + 1];

    /// @brief Length of the textual address representation.
    size_t ipv6_address_buffer_len_;

    /// @brief Length of the prefix (128 for addresses)
    uint8_t prefix_len_;

    /// @brief IAID.
    uint8_t iaid_;

};

/// @brief This class is used for storing IPv6 reservations in a MySQL database.
///
/// This class is only used to insert IPv6 reservations into the
/// ipv6_reservations table. It is not used to retrieve IPv6 reservations. To
/// retrieve IPv6 reservation the @ref MySqlIPv6HostExchange class should be
/// used instead.
///
/// When a new IPv6 reservation is inserted into the database, an appropriate
/// host must be defined in the hosts table. An attempt to insert IPv6
/// reservation for non-existing host will result in failure.
class MySqlIPv6ReservationExchange {
private:

    /// @brief Set number of columns for ipv6_reservation table.
    static const size_t RESRV_COLUMNS = 6;

public:

    /// @brief Constructor
    ///
    /// Initialize class members representing a single IPv6 reservation.
    MySqlIPv6ReservationExchange()
        : host_id_(0), address_("::"), address_len_(0), prefix_len_(0), type_(0),
          iaid_(0), resv_(IPv6Resrv::TYPE_NA, asiolink::IOAddress("::"), 128) {

        // Reset error table.
        std::fill(&error_[0], &error_[RESRV_COLUMNS], MLM_FALSE);

        // Set the column names (for error messages)
        columns_[0] = "host_id";
        columns_[1] = "address";
        columns_[2] = "prefix_len";
        columns_[3] = "type";
        columns_[4] = "dhcp6_iaid";
        BOOST_STATIC_ASSERT(4 < RESRV_COLUMNS);
    }

    /// @brief Create MYSQL_BIND objects for IPv6 Reservation.
    ///
    /// Fills in the MYSQL_BIND array for sending data in the IPv6 Reservation
    /// object to the database.
    ///
    /// @param resv An object representing IPv6 reservation which will be
    ///        sent to the database.
    ///        None of the fields in the reservation are modified -
    ///        the reservation data is only read.
    /// @param id ID of a host owning this reservation
    ///
    /// @return Vector of MySQL BIND objects representing the data to be added.
    std::vector<MYSQL_BIND> createBindForSend(const IPv6Resrv& resv,
                                              const HostID& id) {

        // Store the values to ensure they remain valid.
        resv_ = resv;
        host_id_ = id;

        // Initialize prior to constructing the array of MYSQL_BIND structures.
        // It sets all fields, including is_null, to zero, so we need to set
        // is_null only if it should be true. This gives up minor performance
        // benefit while being safe approach. For improved readability, the
        // code that explicitly sets is_null is there, but is commented out.
        memset(bind_, 0, sizeof(bind_));

        // Set up the structures for the various components of the host structure.

        try {
            // address VARCHAR(39)
            address_ = resv.getPrefix().toText();
            address_len_ = address_.length();
            bind_[0].buffer_type = MYSQL_TYPE_BLOB;
            bind_[0].buffer = reinterpret_cast<char*>
                (const_cast<char*>(address_.c_str()));
            bind_[0].buffer_length = address_len_;
            bind_[0].length = &address_len_;

            // prefix_len tinyint
            prefix_len_ = resv.getPrefixLen();
            bind_[1].buffer_type = MYSQL_TYPE_TINY;
            bind_[1].buffer = reinterpret_cast<char*>(&prefix_len_);
            bind_[1].is_unsigned = MLM_TRUE;

            // type tinyint
            // See lease6_types for values (0 = IA_NA, 1 = IA_TA, 2 = IA_PD)
            type_ = resv.getType() == IPv6Resrv::TYPE_NA ? 0 : 2;
            bind_[2].buffer_type = MYSQL_TYPE_TINY;
            bind_[2].buffer = reinterpret_cast<char*>(&type_);
            bind_[2].is_unsigned = MLM_TRUE;

            // dhcp6_iaid INT UNSIGNED
            /// @todo: We don't support iaid in the IPv6Resrv yet.
            iaid_ = 0;
            bind_[3].buffer_type = MYSQL_TYPE_LONG;
            bind_[3].buffer = reinterpret_cast<char*>(&iaid_);
            bind_[3].is_unsigned = MLM_TRUE;

            // host_id INT UNSIGNED NOT NULL
            bind_[4].buffer_type = MYSQL_TYPE_LONG;
            bind_[4].buffer = reinterpret_cast<char*>(&host_id_);
            bind_[4].is_unsigned = MLM_TRUE;

        } catch (const std::exception& ex) {
            isc_throw(DbOperationError,
                      "Could not create bind array from IPv6 Reservation: "
                      << resv_.toText() << ", reason: " << ex.what());
        }

        // Add the data to the vector.  Note the end element is one after the
        // end of the array.
        // RESRV_COLUMNS -1 as we do not set reservation_id.
        return (std::vector<MYSQL_BIND>(&bind_[0], &bind_[RESRV_COLUMNS-1]));
    }

private:

    /// @brief Host unique identifier.
    uint64_t host_id_;

    /// @brief Address (or prefix).
    std::string address_;

    /// @brief Length of the textual address representation.
    size_t address_len_;

     /// @brief Length of the prefix (128 for addresses).
    uint8_t prefix_len_;

    /// @brief Reservation type.
    uint8_t type_;

    /// @brief IAID.
    uint8_t iaid_;

    /// @brief Object holding reservation being sent to the database.
    IPv6Resrv resv_;

    /// @brief Array of MySQL bindings.
    MYSQL_BIND bind_[RESRV_COLUMNS];

    /// @brief Array of strings holding columns names.
    std::string columns_[RESRV_COLUMNS];

    /// @brief Array of boolean values indicating if error occurred
    /// for respective columns.
    my_bool error_[RESRV_COLUMNS];
};

} // end of anonymous namespace

namespace isc {
namespace dhcp {

/// @brief Implementation of the @ref MySqlHostDataSource.
class MySqlHostDataSourceImpl {
public:

    /// @brief Constructor.
    ///
    /// This constructor opens database connection and initializes prepared
    /// statements used in the queries.
    MySqlHostDataSourceImpl(const MySqlConnection::ParameterMap& parameters);

    /// @brief Destructor.
    ~MySqlHostDataSourceImpl();

    /// @brief Executes query which inserts a row into one of the tables.
    ///
    /// @param stindex Index of a statement being executed.
    /// @param bind Vector of MYSQL_BIND objects to be used when making the
    /// query.
    ///
    /// @throw isc::dhcp::DuplicateEntry Database throws duplicate entry error
    void addQuery(MySqlHostDataSource::StatementIndex stindex,
                  std::vector<MYSQL_BIND>& bind);

    /// @brief Inserts IPv6 Reservation into ipv6_reservation table.
    ///
    /// @param resv IPv6 Reservation to be added
    /// @param id ID of a host owning this reservation
    void addResv(const IPv6Resrv& resv, const HostID& id);

    /// @brief Check Error and Throw Exception
    ///
    /// Virtually all MySQL functions return a status which, if non-zero,
    /// indicates an error.  This inline function conceals a lot of error
    /// checking/exception-throwing code.
    ///
    /// @param status Status code: non-zero implies an error
    /// @param index Index of statement that caused the error
    /// @param what High-level description of the error
    ///
    /// @throw isc::dhcp::DbOperationError An operation on the open database
    ///        has failed.
    void checkError(const int status,
                    const MySqlHostDataSource::StatementIndex index,
                    const char* what) const;

    /// @brief Creates collection of @ref Host objects with associated
    /// information such as IPv6 reservations.
    ///
    /// This method performs a query which returns host information from
    /// the 'hosts' table. The query may also use LEFT JOIN clause to
    /// retrieve information from other tables, e.g. ipv6_reservations.
    /// Whether IPv6 reservations are assigned to the @ref Host objects
    /// depends on the type of the exchange object.
    ///
    /// @param stindex Statement index.
    /// @param bind Pointer to an array of MySQL bindings.
    /// @param exchange Pointer to the exchange object used for the
    /// particular query.
    /// @param [out] result Reference to the collection of hosts returned.
    /// @param single A boolean value indicating if a single host is
    /// expected to be returned, or multiple hosts.
    void getHostCollection(MySqlHostDataSource::StatementIndex stindex,
                           MYSQL_BIND* bind,
                           boost::shared_ptr<MySqlHostExchange> exchange,
                           ConstHostCollection& result, bool single) const;

    /// @brief Retrieves a host by subnet and client's unique identifier.
    ///
    /// This method is used by both MySqlHostDataSource::get4 and
    /// MySqlHOstDataSource::get6 methods.
    ///
    /// @param subnet_id Subnet identifier.
    /// @param identifier_type Identifier type.
    /// @param identifier_begin Pointer to a begining of a buffer containing
    /// an identifier.
    /// @param identifier_len Identifier length.
    /// @param stindex Statement index.
    /// @param exchange Pointer to the exchange object used for the
    /// particular query.
    ///
    /// @return Pointer to const instance of Host or null pointer if
    /// no host found.
    ConstHostPtr getHost(const SubnetID& subnet_id,
                         const Host::IdentifierType& identifier_type,
                         const uint8_t* identifier_begin,
                         const size_t identifier_len,
                         MySqlHostDataSource::StatementIndex stindex,
                         boost::shared_ptr<MySqlHostExchange> exchange) const;

    /// @brief Pointer to the object representing an exchange which
    /// can be used to retrieve DHCPv4 reservation.
    boost::shared_ptr<MySqlHostExchange> host_exchange_;

    /// @brief Pointer to an object representing an exchange which can
    /// be used to retrieve DHCPv6 reservations.
    boost::shared_ptr<MySqlHostIPv6Exchange> host_ipv6_exchange_;

    /// @brief Pointer to an object representing an exchange which can
    /// be used to insert new IPv6 reservation.
    boost::shared_ptr<MySqlIPv6ReservationExchange> host_ipv6_reservation_exchange_;

    /// @brief MySQL connection
    MySqlConnection conn_;

};

MySqlHostDataSourceImpl::
MySqlHostDataSourceImpl(const MySqlConnection::ParameterMap& parameters)
    : host_exchange_(new MySqlHostExchange()),
      host_ipv6_exchange_(new MySqlHostIPv6Exchange()),
      host_ipv6_reservation_exchange_(new MySqlIPv6ReservationExchange()),
      conn_(parameters) {

    // Open the database.
    conn_.openDatabase();

    // Enable autocommit.  To avoid a flush to disk on every commit, the global
    // parameter innodb_flush_log_at_trx_commit should be set to 2.  This will
    // cause the changes to be written to the log, but flushed to disk in the
    // background every second.  Setting the parameter to that value will speed
    // up the system, but at the risk of losing data if the system crashes.
    my_bool result = mysql_autocommit(conn_.mysql_, 1);
    if (result != 0) {
        isc_throw(DbOperationError, mysql_error(conn_.mysql_));
    }

    // Prepare all statements likely to be used.
    conn_.prepareStatements(tagged_statements,
            MySqlHostDataSource::NUM_STATEMENTS);
}

MySqlHostDataSourceImpl::~MySqlHostDataSourceImpl() {
    // Free up the prepared statements, ignoring errors. (What would we do
    // about them? We're destroying this object and are not really concerned
    // with errors on a database connection that is about to go away.)
    for (int i = 0; i < conn_.statements_.size(); ++i) {
        if (conn_.statements_[i] != NULL) {
            (void) mysql_stmt_close(conn_.statements_[i]);
            conn_.statements_[i] = NULL;
        }
    }

    // There is no need to close the database in this destructor: it is
    // closed in the destructor of the mysql_ member variable.
}

void
MySqlHostDataSourceImpl::addQuery(MySqlHostDataSource::StatementIndex stindex,
                                  std::vector<MYSQL_BIND>& bind) {

    // Bind the parameters to the statement
    int status = mysql_stmt_bind_param(conn_.statements_[stindex], &bind[0]);
    checkError(status, stindex, "unable to bind parameters");

    // Execute the statement
    status = mysql_stmt_execute(conn_.statements_[stindex]);
    if (status != 0) {
        // Failure: check for the special case of duplicate entry.
        if (mysql_errno(conn_.mysql_) == ER_DUP_ENTRY) {
            isc_throw(DuplicateEntry, "Database duplicate entry error");
        }
        checkError(status, stindex, "unable to execute");
    }
}

void
MySqlHostDataSourceImpl::addResv(const IPv6Resrv& resv,
                                 const HostID& id) {
    std::vector<MYSQL_BIND> bind =
        host_ipv6_reservation_exchange_->createBindForSend(resv, id);

    addQuery(MySqlHostDataSource::INSERT_V6_RESRV, bind);
}

void
MySqlHostDataSourceImpl::
checkError(const int status, const MySqlHostDataSource::StatementIndex index,
           const char* what) const {
    if (status != 0) {
        isc_throw(DbOperationError, what << " for <"
                  << conn_.text_statements_[index] << ">, reason: "
                  << mysql_error(conn_.mysql_) << " (error code "
                  << mysql_errno(conn_.mysql_) << ")");
    }
}

void
MySqlHostDataSourceImpl::
getHostCollection(MySqlHostDataSource::StatementIndex stindex,
                  MYSQL_BIND* bind, boost::shared_ptr<MySqlHostExchange> exchange,
                  ConstHostCollection& result, bool single) const {

    // Bind the selection parameters to the statement
    int status = mysql_stmt_bind_param(conn_.statements_[stindex], bind);
    checkError(status, stindex, "unable to bind WHERE clause parameter");

    // Set up the MYSQL_BIND array for the data being returned and bind it to
    // the statement.
    std::vector<MYSQL_BIND> outbind = exchange->createBindForReceive();
    status = mysql_stmt_bind_result(conn_.statements_[stindex], &outbind[0]);
    checkError(status, stindex, "unable to bind SELECT clause parameters");

    // Execute the statement
    status = mysql_stmt_execute(conn_.statements_[stindex]);
    checkError(status, stindex, "unable to execute");

    // Ensure that all the lease information is retrieved in one go to avoid
    // overhead of going back and forth between client and server.
    status = mysql_stmt_store_result(conn_.statements_[stindex]);
    checkError(status, stindex, "unable to set up for storing all results");

    // Set up the fetch "release" object to release resources associated
    // with the call to mysql_stmt_fetch when this method exits, then
    // retrieve the data. mysql_stmt_fetch return value equal to 0 represents
    // successful data fetch.
    MySqlFreeResult fetch_release(conn_.statements_[stindex]);
    while ((status = mysql_stmt_fetch(conn_.statements_[stindex])) ==
           MLM_MYSQL_FETCH_SUCCESS) {
        try {
            exchange->processFetchedData(result);

        } catch (const isc::BadValue& ex) {
            // Rethrow the exception with a bit more data.
            isc_throw(BadValue, ex.what() << ". Statement is <" <<
                    conn_.text_statements_[stindex] << ">");
        }

        if (single && (result.size() > 1)) {
            isc_throw(MultipleRecords, "multiple records were found in the "
                      "database where only one was expected for query "
                      << conn_.text_statements_[stindex]);
        }
    }

    // How did the fetch end?
    // If mysql_stmt_fetch return value is equal to 1 an error occurred.
    if (status == MLM_MYSQL_FETCH_FAILURE) {
        // Error - unable to fetch results
        checkError(status, stindex, "unable to fetch results");

    } else if (status == MYSQL_DATA_TRUNCATED) {
        // Data truncated - throw an exception indicating what was at fault
        isc_throw(DataTruncated, conn_.text_statements_[stindex]
                  << " returned truncated data: columns affected are "
                  << exchange->getErrorColumns());
    }
}

ConstHostPtr
MySqlHostDataSourceImpl::
getHost(const SubnetID& subnet_id,
        const Host::IdentifierType& identifier_type,
        const uint8_t* identifier_begin,
        const size_t identifier_len,
        MySqlHostDataSource::StatementIndex stindex,
        boost::shared_ptr<MySqlHostExchange> exchange) const {

    // Set up the WHERE clause value
    MYSQL_BIND inbind[3];
    memset(inbind, 0, sizeof(inbind));

    uint32_t subnet_buffer = static_cast<uint32_t>(subnet_id);
    inbind[0].buffer_type = MYSQL_TYPE_LONG;
    inbind[0].buffer = reinterpret_cast<char*>(&subnet_buffer);
    inbind[0].is_unsigned = MLM_TRUE;

    // Identifier value.
    std::vector<char> identifier_vec(identifier_begin,
                                     identifier_begin + identifier_len);
    unsigned long length = identifier_vec.size();
    inbind[2].buffer_type = MYSQL_TYPE_BLOB;
    inbind[2].buffer = &identifier_vec[0];
    inbind[2].buffer_length = length;
    inbind[2].length = &length;

    // Identifier type.
    char identifier_type_copy = static_cast<char>(identifier_type);
    inbind[1].buffer_type = MYSQL_TYPE_TINY;
    inbind[1].buffer = reinterpret_cast<char*>(&identifier_type_copy);
    inbind[1].is_unsigned = MLM_TRUE;

    ConstHostCollection collection;
    getHostCollection(stindex, inbind, exchange, collection, true);

    // Return single record if present, else clear the host.
    ConstHostPtr result;
    if (!collection.empty())
        result = *collection.begin();

    return (result);
}


MySqlHostDataSource::
MySqlHostDataSource(const MySqlConnection::ParameterMap& parameters)
    : impl_(new MySqlHostDataSourceImpl(parameters)) {
}

MySqlHostDataSource::~MySqlHostDataSource() {
    delete impl_;
}

void
MySqlHostDataSource::add(const HostPtr& host) {
    // Create the MYSQL_BIND array for the host
    std::vector<MYSQL_BIND> bind = impl_->host_exchange_->createBindForSend(host);

    // ... and call addHost() code.
    impl_->addQuery(INSERT_HOST, bind);

    IPv6ResrvRange v6resv = host->getIPv6Reservations();
    if (std::distance(v6resv.first, v6resv.second) == 0) {
        // If there are no v6 reservations, we're done here.
        return;
    }

    // Gets the last inserted hosts id
    uint64_t host_id = mysql_insert_id(impl_->conn_.mysql_);
    for (IPv6ResrvIterator resv = v6resv.first; resv != v6resv.second;
         ++resv) {
        impl_->addResv(resv->second, host_id);
    }
}

ConstHostCollection
MySqlHostDataSource::getAll(const HWAddrPtr& hwaddr,
                            const DuidPtr& duid) const {

    if (duid){
        return (getAll(Host::IDENT_DUID, &duid->getDuid()[0],
                       duid->getDuid().size()));

    } else if (hwaddr) {
        return (getAll(Host::IDENT_HWADDR,
                       &hwaddr->hwaddr_[0],
                       hwaddr->hwaddr_.size()));
    }

    return (ConstHostCollection());
}

ConstHostCollection
MySqlHostDataSource::getAll(const Host::IdentifierType& identifier_type,
                            const uint8_t* identifier_begin,
                            const size_t identifier_len) const {
    // Set up the WHERE clause value
    MYSQL_BIND inbind[2];
    memset(inbind, 0, sizeof(inbind));

    // Identifier type.
    char identifier_type_copy = static_cast<char>(identifier_type);
    inbind[1].buffer = &identifier_type_copy;
    inbind[1].buffer_type = MYSQL_TYPE_TINY;
    inbind[1].is_unsigned = MLM_TRUE;

    // Identifier value.
    std::vector<char> identifier_vec(identifier_begin,
                                     identifier_begin + identifier_len);
    unsigned long int length = identifier_vec.size();
    inbind[0].buffer_type = MYSQL_TYPE_BLOB;
    inbind[0].buffer = &identifier_vec[0];
    inbind[0].buffer_length = length;
    inbind[0].length = &length;

    ConstHostCollection result;
    impl_->getHostCollection(GET_HOST_DHCPID, inbind,
                             impl_->host_ipv6_exchange_,
                             result, false);
    return (result);
}

ConstHostCollection
MySqlHostDataSource::getAll4(const asiolink::IOAddress& address) const {

    // Set up the WHERE clause value
    MYSQL_BIND inbind[1];
    memset(inbind, 0, sizeof(inbind));

    uint32_t addr4 = static_cast<uint32_t>(address);
    inbind[0].buffer_type = MYSQL_TYPE_LONG;
    inbind[0].buffer = reinterpret_cast<char*>(&addr4);
    inbind[0].is_unsigned = MLM_TRUE;

    ConstHostCollection result;
    impl_->getHostCollection(GET_HOST_ADDR, inbind, impl_->host_exchange_,
                             result, false);

    return (result);
}

ConstHostPtr
MySqlHostDataSource::get4(const SubnetID& subnet_id, const HWAddrPtr& hwaddr,
                          const DuidPtr& duid) const {

    /// @todo: Rethink the logic in BaseHostDataSource::get4(subnet, hwaddr, duid)
    if (hwaddr && duid) {
        isc_throw(BadValue, "MySQL host data source get4() called with both"
                  " hwaddr and duid, only one of them is allowed");
    }
    if (!hwaddr && !duid) {
        isc_throw(BadValue, "MySQL host data source get4() called with "
                  "neither hwaddr or duid specified, one of them is required");
    }

    // Choosing one of the identifiers
    if (hwaddr) {
        return (get4(subnet_id, Host::IDENT_HWADDR, &hwaddr->hwaddr_[0],
                     hwaddr->hwaddr_.size()));

    } else if (duid) {
        return (get4(subnet_id, Host::IDENT_DUID, &duid->getDuid()[0],
                     duid->getDuid().size()));
    }

    return (ConstHostPtr());
}

ConstHostPtr
MySqlHostDataSource::get4(const SubnetID& subnet_id,
                          const Host::IdentifierType& identifier_type,
                          const uint8_t* identifier_begin,
                          const size_t identifier_len) const {

    return (impl_->getHost(subnet_id, identifier_type, identifier_begin,
                   identifier_len, GET_HOST_SUBID4_DHCPID,
                   impl_->host_exchange_));
}

ConstHostPtr
MySqlHostDataSource::get4(const SubnetID& subnet_id,
                          const asiolink::IOAddress& address) const {

    // Set up the WHERE clause value
    MYSQL_BIND inbind[2];
    uint32_t subnet = subnet_id;
    memset(inbind, 0, sizeof(inbind));
    inbind[0].buffer_type = MYSQL_TYPE_LONG;
    inbind[0].buffer = reinterpret_cast<char*>(&subnet);
    inbind[0].is_unsigned = MLM_TRUE;

    uint32_t addr4 = static_cast<uint32_t>(address);
    inbind[1].buffer_type = MYSQL_TYPE_LONG;
    inbind[1].buffer = reinterpret_cast<char*>(&addr4);
    inbind[1].is_unsigned = MLM_TRUE;

    ConstHostCollection collection;
    impl_->getHostCollection(GET_HOST_SUBID_ADDR, inbind, impl_->host_exchange_,
                             collection, true);

    // Return single record if present, else clear the host.
    ConstHostPtr result;
    if (!collection.empty())
        result = *collection.begin();

    return (result);
}

ConstHostPtr
MySqlHostDataSource::get6(const SubnetID& subnet_id, const DuidPtr& duid,
                          const HWAddrPtr& hwaddr) const {

    /// @todo: Rethink the logic in BaseHostDataSource::get6(subnet, hwaddr, duid)
    if (hwaddr && duid) {
        isc_throw(BadValue, "MySQL host data source get6() called with both"
                  " hwaddr and duid, only one of them is allowed");
    }
    if (!hwaddr && !duid) {
        isc_throw(BadValue, "MySQL host data source get6() called with "
                  "neither hwaddr or duid specified, one of them is required");
    }

    // Choosing one of the identifiers
    if (hwaddr) {
        return (get6(subnet_id, Host::IDENT_HWADDR, &hwaddr->hwaddr_[0],
                     hwaddr->hwaddr_.size()));
    } else if (duid) {
        return (get6(subnet_id, Host::IDENT_DUID, &duid->getDuid()[0],
                     duid->getDuid().size()));
    }

    return (ConstHostPtr());
}

ConstHostPtr
MySqlHostDataSource::get6(const SubnetID& subnet_id,
                          const Host::IdentifierType& identifier_type,
                          const uint8_t* identifier_begin,
                          const size_t identifier_len) const {

    return (impl_->getHost(subnet_id, identifier_type, identifier_begin,
                   identifier_len, GET_HOST_SUBID6_DHCPID,
                   impl_->host_ipv6_exchange_));
}

ConstHostPtr
MySqlHostDataSource::get6(const asiolink::IOAddress& prefix,
                          const uint8_t prefix_len) const {

    // Set up the WHERE clause value
    MYSQL_BIND inbind[2];
    memset(inbind, 0, sizeof(inbind));

    std::string addr6 = prefix.toText();
    unsigned long addr6_length = addr6.size();

    inbind[0].buffer_type = MYSQL_TYPE_BLOB;
    inbind[0].buffer = reinterpret_cast<char*>
                        (const_cast<char*>(addr6.c_str()));
    inbind[0].length = &addr6_length;
    inbind[0].buffer_length = addr6_length;


    uint8_t tmp = prefix_len;
    inbind[1].buffer_type = MYSQL_TYPE_TINY;
    inbind[1].buffer = reinterpret_cast<char*>(&tmp);
    inbind[1].is_unsigned = MLM_TRUE;


    ConstHostCollection collection;
    impl_->getHostCollection(GET_HOST_PREFIX, inbind,
                             impl_->host_ipv6_exchange_,
                             collection, true);

    // Return single record if present, else clear the host.
    ConstHostPtr result;
    if (!collection.empty()) {
        result = *collection.begin();
    }

    return (result);
}

// Miscellaneous database methods.

std::string MySqlHostDataSource::getName() const {
    std::string name = "";
    try {
        name = impl_->conn_.getParameter("name");
    } catch (...) {
        // Return an empty name
    }
    return (name);
}

std::string MySqlHostDataSource::getDescription() const {
    return (std::string("Host data source that stores host information"
                        "in MySQL database"));
}

std::pair<uint32_t, uint32_t> MySqlHostDataSource::getVersion() const {
    const StatementIndex stindex = GET_VERSION;

    LOG_DEBUG(dhcpsrv_logger, DHCPSRV_DBG_TRACE_DETAIL,
              DHCPSRV_MYSQL_HOST_DB_GET_VERSION);

    uint32_t major;      // Major version number
    uint32_t minor;      // Minor version number

    // Execute the prepared statement
    int status = mysql_stmt_execute(impl_->conn_.statements_[stindex]);
    if (status != 0) {
        isc_throw(DbOperationError, "unable to execute <"
                  << impl_->conn_.text_statements_[stindex]
                  << "> - reason: " << mysql_error(impl_->conn_.mysql_));
    }

    // Bind the output of the statement to the appropriate variables.
    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].is_unsigned = 1;
    bind[0].buffer = &major;
    bind[0].buffer_length = sizeof(major);

    bind[1].buffer_type = MYSQL_TYPE_LONG;
    bind[1].is_unsigned = 1;
    bind[1].buffer = &minor;
    bind[1].buffer_length = sizeof(minor);

    status = mysql_stmt_bind_result(impl_->conn_.statements_[stindex], bind);
    if (status != 0) {
        isc_throw(DbOperationError, "unable to bind result set: "
                  << mysql_error(impl_->conn_.mysql_));
    }

    // Fetch the data and set up the "release" object to release associated
    // resources when this method exits then retrieve the data.
    // mysql_stmt_fetch return value other than 0 means error occurrence.
    MySqlFreeResult fetch_release(impl_->conn_.statements_[stindex]);
    status = mysql_stmt_fetch(impl_->conn_.statements_[stindex]);
    if (status != 0) {
        isc_throw(DbOperationError, "unable to obtain result set: "
                  << mysql_error(impl_->conn_.mysql_));
    }

    return (std::make_pair(major, minor));
}

void
MySqlHostDataSource::commit() {
    impl_->conn_.commit();
}


void
MySqlHostDataSource::rollback() {
    impl_->conn_.rollback();
}


}; // end of isc::dhcp namespace
}; // end of isc namespace
