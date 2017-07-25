#!/usr/bin/python

# Copyright 2016 Oracle Corporation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import ConfigParser
import grp
import iniparse
import os
import platform
import pwd
import shutil
import socket
import sys
import time
import warnings
import MySQLdb

from M2Crypto import RSA
from solaris_install import with_spinner
from subprocess import CalledProcessError, Popen, PIPE, check_call, call, check_output
from os import listdir
from os.path import isfile, join

# Set True if single node deployment
SINGLE_NODE = True

MY_NAME = platform.node()
MY_IP = socket.gethostbyname(MY_NAME)

if SINGLE_NODE:
    CONTROLLER_NODE = MY_NAME
    COMPUTE_NODE = MY_NAME
    HORIZON_HOSTNAME = MY_NAME
else:
    # For multinode, the hostname facing the internal network
    # with Openstack services needs to be specified
    CONTROLLER_NODE = "ctl-net1.us.oracle.com"
    COMPUTE_NODE = "comp0-net1.us.oracle.com"
    HORIZON_HOSTNAME = "ctl-net0.us.oracle.com"

REGION_NAME = "RegionOne"

# Change below values if you're performing multi-node setup
# outside of the standard controller / compute configuraton
# that the arguments use.
AI_NODE = CONTROLLER_NODE
DB_NODE = CONTROLLER_NODE
KEYSTONE_NODE = CONTROLLER_NODE
GLANCE_NODE = CONTROLLER_NODE
CINDER_NODE = CONTROLLER_NODE
NEUTRON_NODE = CONTROLLER_NODE
RABBIT_NODE = CONTROLLER_NODE
HEAT_NODE = CONTROLLER_NODE
SWIFT_NODE = CONTROLLER_NODE
IRONIC_NODE = CONTROLLER_NODE
NOVA_NODE = CONTROLLER_NODE
NOVA_METADATA_NODE = CONTROLLER_NODE

# Set True if AI server is on the controller node
AI_ON_CONTROLLER = False

USE_CEILOMETER = False
# PASSWORDS
# Default passwords
# Horizon is un:$ADMIN_USER pw:$ADMIN_PASSWORD
# or un:$DEFAULT_PROJCT pw:$ADMIN_PASSWORD
ADMIN_USER = "admin"
ADMIN_PASSWORD = "adminpw"
SERVICE_PASSWORD = "servicepw"

SERVICE_PROJECT = "service"
DEFAULT_PROJECT = "proj_admin"

MYSQL_ROOTPW = "mysqlroot"
# Used for Neutron and Nova metadata server to communicate
NOVA_METADATA_SECRET = "seCr3t"

RABBITMQ_USER = "openstack"
RABBITMQ_PASS = "openstack"

########## NETWORKING CONFIGURATION #########################

#### UPLINK TO TENANT COMPUTE INSTANCES ######
# FOR SINGLE NODE CONFIG
#
# EXT_UPLINK_PORT = "net0"
# INT_UPLINK_PORT = "l3stub0"
#                                                  PF filtering
#                                         +------>  rules + PBR
#                                         |         (route-to)
#                                         |
# +---------------------------------------+-------------------------------------------------+
# |                                       |                                                 |
# |                                       |                                                 |
# |                                       |                                                 |
# |                                       |                                                 |
# |                                       |   +---------------+  +---------------+          |
# |                                       |   |   dh* vnic3   |  |   dh* vnic4   |          |
# |                                       |   | 192.168.94.2  |  | 192.168.93.2  |          |
# |           IP                          |   +-------+-------+  +-+-------------+          |
# |       Forwarding              +---------------+   |            |   +------------------+ |
# |        Enabled                |  l3i* vnic1   |   |            |   |   TenantA VM1    | |
# |                               | 192.168.94.1  +---+-----+------+---+(192.168.94.3/24) | |
# |                               +---------------+         |          +------------------+ |
# |                               +---------------+         |          +------------------+ |
# |                               |  l3i* vnic2   |         |          |   TenantB VM2    | |
# |                               | 192.168.93.1  |---------+----------+(192.168.93.4/24) | |
# |                               +---------------+         |          +------------------+ |
# |                                                         v                               |
# |                                                +------------------+                     |
# |     +-------------+ +--------------+           |     l3stub0      |                     |
# |     |    net0     | |  l3e* vnic   |           +------------------+                     |
# |     |10.134.13.79 | |10.134.240.210|--------+                                           |
# |     +-------------+ +--------------+        |                                           |
# |     +------------------------------+        |                                           |
# +-----+             net0             +--------+-------------------------------------------+
#       +----------------------^-------+        |
#                              |                |         PF translation
#                              |                +--------> rules (bi-nat
#                              |                            and nat-to)
#                              v
#                     +-------------------+
#                     |     Internet      |
#                     +-------------------+

# FOR MULTINODE CONFIG
#
# EXT_UPLINK_PORT = "net0"
# INT_UPLINK_PORT = "net2"
#
# (Network Node)---------------------------------+    (compute)--------------+
# |                      IP                      |    |                      |
# |                   Forwrding                  |    |                      |
# |                 + - - - - - +                |    |                      |
# |                                              |    | +-----------------+  |
# |                 v           |                |    | |                 |  |
# |        +-----------------+                   |    | |instance-00000053|  |
# |        |10.134.12.200/24 |  |                |    | |  (solaris-kz)   |  |
# |        |10.134.12.201/32 |     +----++----+  |    | |  192.168.93.2   |  |
# |        +--+----+---------+  |  |l3i*||dh* |  |    | |  10.134.12.201  |  |
# |+--------+ |l3e*|             ->|VNIC||VNIC|  |    | |                 |  |
# ||10.134.1| |VNIC|               +----++----+  |    | +-----------------+  |
# ||3.79/24 | |    |                +---------+  |    | +---------+          |
# |+--+-----+-+----+                |  net2   |  |    | |  net2   |          |
# +---+    net0    +----------------+         +--+    +-+         +----------+
#     +------------+                +---------+         +---------+
#            |                           ^                   ^
#            +---+                       |                   |
#                |                       +-------------------+
#                v
#       +-------------------+
#       |     Internet      |
#       +-------------------+
#

# Specify the port going to the external network, WAN aka internet
EXT_UPLINK_PORT = "net0"

# Port to the interenal tenant network where compute nodes are reachable
if SINGLE_NODE:
    # Used to prevent certain broadcast and multicast from leaving the
    # system and beig dropped.
    INT_UPLINK_PORT = "l3stub0"
else:
    # The interface facing the internal Openstack control network
    # where compute nodes are reachable
    INT_UPLINK_PORT = "net1"

# ["flat", "vlan", "vxlan"]
if SINGLE_NODE:
    # etherstub only allows vlan
    INT_L2_LAN_TYPE = "vlan"
else:
    INT_L2_LAN_TYPE = "vxlan"

# V[X]LAN tag range for internal_subnets
INT_L2_TAG_RANGE = "10-13"

# Allows compute instances in different tenants to talk to
# each other.
L3_AGENT_FORWARD_BETWEEEN_TENANTS = False

# {"flat", "vlan", "vxlan"}
EXT_NETWORK_TYPE = "flat"
# If v[x]lan specified, the tag external network uses
EXT_NETWORK_TAG = "1"
# External network gateway
EXT_NETWORK_GATEWAY = "192.168.0.1"
# External network subnet
EXT_NETWORK_ADDR = "192.168.0.0/24"
# External network DNS server
EXT_NETWORK_DNS = "192.168.0.1"

# Do not allocate any floating IPs. Note, that the
# Heat Orchestration stacks may require a floating IP
# so this should be False if testing Heat
EXT_NETWORK_NO_FLOAT_IP = False
EXT_NETWORK_SNAT_IP = "10.80.162.250"

# This is where you ask netops for external floating
# IP range.  The floating IP will only be assigned if
# requested after VM creation.
EXT_NETWORK_STARTIP = "192.168.0.25"
EXT_NETWORK_STOPIP = "192.168.0.250"

EXT_NETWORK_NAME = "external"

if EXT_NETWORK_NO_FLOAT_IP:
    IP_RANGE_AVAIL = 0
else:
    IP_RANGE_AVAIL = 6

# Quota of IPs for tenant
IP_QUOTA_TENANT = IP_RANGE_AVAIL
# Allocate half of the range for floating IPs
IP_ALLOC_TENANT = IP_RANGE_AVAIL / 2

# Default tenants to create for demo purposes.  Ensure TENANT_COUNT is correct
# admin_user_name, proj_name, network_name, internal_subnet, quota_floating_ips, alloc_floating_ips
TENANT_NET_LIST = [("admin_proj_0000", ADMIN_PASSWORD, "proj_0001","192.168.100.0/24", IP_QUOTA_TENANT, IP_ALLOC_TENANT),
                   ("admin_proj_0001", ADMIN_PASSWORD, "proj_0002", "192.168.200.0/24", IP_QUOTA_TENANT, IP_ALLOC_TENANT)]

#############################################################

# Set to True if you want to use TLS/SSL
# Currently this script will enable TLS/SSL accross all services
# that support it.
USE_SSL = True
RABBITMQ_USE_SSL = False

# If True, generate our own root CA, intermediate CA and
# self signed certificates for testing purposes
if USE_SSL:
    SSL_GEN_CACERTS = True
else:
    SSL_GEN_CACERTS = False

SOL_CACERTS_FILE = "/etc/certs/ca-certificates.crt"

if not SSL_GEN_CACERTS:
    # Supply paths to your own certs for this node.  These will be copied
    # to appropriate locations with correct uid/gid and permissions.
    SSL_CACERT_FILE = "~/certs/intermediate.cert.pem"
    SSL_CACHAINCERT_FILE = "~/certs/ca-chain.cert.pem"
    SSL_SERVER_CERT_FILE = "~/certs/server.cert.pem"
    SSL_SERVER_CERT_FCHAIN_FILE = "~/certs/server-fchain.cert.pem"
    SSL_SERVER_KEY_FILE = "~/private/server.key.pem"
    SSL_HZN_SERVER_CERT_FILE = "~/certs/hzn-server.cert.pem"
    SSL_HZN_SERVER_CERT_FCHAIN_FILE = "~/certs/hzn-server-fchain.cert.pem"
    SSL_HZN_SERVER_KEY_FILE = "~/private/hzn-server.key.pem"

    SSL_CLIENT_CERT_FILE = "~/certs/osclient-client.cert.pem"
    SSL_CLIENT_KEY_FILE = "~/private/osclient-client.key.pem"

# Choose the method of storing OS images
# File is default.  Swift and S3 are other options
# if the image data is large and desire is to distribute it
# over multiple nodes.
#
# { "file", "swift" }
#
# Note: only file and swift have been tested
GLANCE_STORE = "file"

NEUTRON_ROUTER_NAME = "cloud_router"

# ZPOOL configuration for services
GLANCE_ZPOOL = "rpool"
#GLANCE_ZPOOL = "tank"
GLANCE_DATASET = "%s/glance" % GLANCE_ZPOOL
CINDER_ZPOOL = GLANCE_ZPOOL
CINDER_DATASET = "%s/cinder" % CINDER_ZPOOL
SWIFT_ZPOOL = GLANCE_ZPOOL
SWIFT_DATASET = "%s/swift" % SWIFT_ZPOOL
SWIFT_SRV_DATASET = "%s/swift/srv" % SWIFT_ZPOOL
SWIFT_NODE_DATASET = "%s/swift/srv/node" % SWIFT_ZPOOL

######### BLOCK STORAGE #################################
# {"zfslocal", "zfsiscsi", "zfssaiscsi"}
# zfslocal: use local ZFS volume for block storage
# zfsiscsi: use iscsi for block storage.  Cinder block storage
#           and Nova compute must be on different nodes
# zfssaiscsi: use ZFS storage appliance for block storage. See
#             following section on configuring ZFS SA
#
# Generally, zfslocal should be used for singlenode configuration,
# zfsiscsi should be used for multinode configuration.
#
#
CINDER_STORE = "zfslocal"
# Use ZFS compression for zfslocal block storage
CINDER_COMPRESS_DATA = True

######## ZFSSA CONFIGURATION ############################
# Refer to:
# https://docs.oracle.com/cd/E65465_01/html/E57770/zfssadriver.html
# http://www.oracle.com/technetwork/server-storage/sun-unified-storage/documentation/openstack-cinder-zfssa-120915-2813178.pdf
ZFSSA_MGT_HOST = "zfsserver-mgmt-hostname"
# These values are obtained running ZFSSA workflow described
# above.
ZFSSA_CINDER_USER = "openstack"
ZFSSA_CINDER_PASSWORD = "openstack"
# pool name is in WebGUI configuration->storage->NAME
ZFSSA_POOL = "pool-name"
# This is the fast networking interface to ZFSSA
ZFSSA_TARGET_PORTAL = "192.168.0.200:3260"
ZFSSA_PROJECT = "openstack-project"
# this is a comma separated list for each compute node
# invoke following on compute and controller node and use first line
# $ iscsiadm list initiator-node
ZFSSA_INITIATOR = """iqn.1986-03.com.sun:01:e00000000000.55535041,
iqn.1986-03.com.sun:01:a35ba860aff8.5745c95c"""
# default is ok to start, however it's recommended to create
# a different group.
ZFSSA_TARGET_GROUP = "default"
ZFSSA_INIT_GROUP = "default"
# ZFSSA network interface facing compute nodes
ZFSSA_TARGET_INTFS = "nge1"
##### IMAGES #########
# Script will add all images in this directory to Glance
# It is able to detect the architecture of the UAR automatically
GLANCE_IMAGE_SOURCE_DIR = "./images"
############################################################
# Increase timeout for Keystone response
NOVA_SLOW_KEYSTONE = False

############ END CONFIGURATION ###############################

nodelist = [DB_NODE, KEYSTONE_NODE, GLANCE_NODE, CINDER_NODE,
        NEUTRON_NODE, RABBIT_NODE, HEAT_NODE, SWIFT_NODE,
        IRONIC_NODE, NOVA_METADATA_NODE, HORIZON_HOSTNAME]

# Used for multi-node testing
BUNDLE_PATH = os.getcwd()
BUNDLE_FILE = BUNDLE_PATH + "/bundle.tgz"
BUNDLE_PREP_PATH = os.getcwd() + "/.bundle_prep"
BUNDLE_PREP_PATH_BASE = BUNDLE_PREP_PATH + "/os_kilo_setup"

# Temporarily used to bootstrap Keystone and then
# disabled.
SERVICE_TOKEN = "ADMIN"

# Identity URLs
if USE_SSL:
    AUTH_URI = "https://%s:5000/" % KEYSTONE_NODE
    AUTH_URL = "https://%s:35357/" % KEYSTONE_NODE
else:
    AUTH_URI = "http://%s:5000/" % KEYSTONE_NODE
    AUTH_URL = "http://%s:35357/" % KEYSTONE_NODE

IDENTITY_URI = AUTH_URL
IDENTITY_V2 = "2"
PUBLIC_ENDPOINT_V2 = AUTH_URI + "v2.0/"
SERVICE_ENDPOINT_V2 = AUTH_URL + "v2.0/"
PUBLIC_ENDPOINT = PUBLIC_ENDPOINT_V2
SERVICE_ENDPOINT = SERVICE_ENDPOINT_V2
#############################################################

def drop_db(cursor, dbname):
    print "removing %s database" % dbname
    try:
        cursor.execute("DROP DATABASE {0};".format(dbname))
        cursor.execute("DELETE FROM mysql.db WHERE Db='{0}' OR "
                "Db='{0}\\_%'".format(dbname))
    except Exception as inst:
        print "err %s" % inst

def create_db(cursor, dbname):
    print "Creating database %s" % dbname

    cursor.execute("CREATE DATABASE {0} DEFAULT CHARACTER SET utf8 "
                   "DEFAULT COLLATE utf8_general_ci;".format(dbname))
    user_name = "nova" if dbname == "nova_api" else dbname
    if USE_SSL:
        cursor.execute("GRANT ALL PRIVILEGES ON %s.* TO '%s'@'localhost'"
                " IDENTIFIED BY '%s-pass' REQUIRE SSL;" % (dbname, user_name, user_name))
        cursor.execute("GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' IDENTIFIED BY "
                "'%s-pass' REQUIRE SSL;" % (dbname, user_name, user_name))
    else:
        cursor.execute("GRANT ALL PRIVILEGES ON %s.* TO '%s'@'localhost' IDENTIFIED "
                        "BY '%s-pass';" % (dbname, user_name, user_name))
        cursor.execute("GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' IDENTIFIED BY "
                        "'%s-pass';" % (dbname, user_name, user_name))

db_list = ['keystone', 'glance', 'cinder', 'neutron', 'heat',
           'ironic', 'nova', 'nova_api']

# DEBUG
def mysql_db_destroy(d):
    db = MySQLdb.connect("localhost", "root", MYSQL_ROOTPW)
    cursor = db.cursor()
    drop_db(cursor, d)
    db.commit()
    db.close()

def mysql_db_destroy_all():
    for dbn in db_list:
        mysql_db_destroy(dbn)

def mysql_db_create_db(d):
    db = MySQLdb.connect("localhost", "root", MYSQL_ROOTPW)
    cursor = db.cursor()
    create_db(cursor, d)
    db.commit()
    db.close()

def mysql_db_create():
    db = MySQLdb.connect("localhost", "root", MYSQL_ROOTPW)
    cursor = db.cursor()
    for d in db_list:
        create_db(cursor, d)
    db.commit()
    db.close()

# Configures MySQL and creates databases
def mysql(pw_configured=False):
    # install mysql if needed and start it
    pkg_install(['mysql-55', 'mysql-55/client', 'python-mysql'])

    if USE_SSL:
        service = "mysql"
        servercert = get_ssl_path(service, "servercert")
        serverkey = get_ssl_path(service, "serverkey")
        populate_cert_dirs("mysql")

        cmd = ["/usr/bin/gsed",
            "-e", "/\[mysqld\]/a ssl-ca = \"%s\"" % SOL_CACERTS_FILE,
            "-e", "/\[mysqld\]/a ssl-cert = \"%s\"" % servercert,
            "-e", "/\[mysqld\]/a ssl-key = \"%s\"" % serverkey]

        # Update global MySQL config file with values
        fd, tf = tempfile.mkstemp()
        # Copy to temp location
        shutil.copyfile("/etc/mysql/5.5/my.cnf", tf)
        myinput = open(tf)
        myoutput = open("/etc/mysql/5.5/my.cnf", "w")
        # Run sed
        p = Popen(cmd, stdout=myoutput, stderr=PIPE, stdin=myinput)
        p.wait()
        myoutput.flush()
        myinput.close()
        os.close(fd)
        os.remove(tf)

    cmd = ["/usr/bin/svcs", "-H", "-o", "state", "mysql"]
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if out.strip() == "disabled":
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "mysql"])

    # OIB v
    time.sleep(2)

    if not pw_configured:
        # Open database connection
        for i in range(5):
            try:
                db = MySQLdb.connect('localhost', 'root')
                cursor = db.cursor()
                print "setting root password"
                cursor.execute("UPDATE mysql.user "
                        "SET Password=PASSWORD('%s') WHERE "
                        "User='root';" % MYSQL_ROOTPW)
                cursor.execute("FLUSH PRIVILEGES;")
                db.close()
                break
            except Exception as err:
                # wait for db to come up
                time.sleep(2)
        else:
            # Maybe root PW setup
            sys.exit('unable to connect to mysql: %s' % err)

    # prepare a cursor object using cursor() method
    db = MySQLdb.connect("localhost", "root", MYSQL_ROOTPW)
    cursor = db.cursor()

    print "removing anonymous users"
    cursor.execute("DELETE FROM mysql.user WHERE User='';")

    print "removing remote root"
    cursor.execute("DELETE FROM mysql.user WHERE User='root' AND "
            "Host NOT IN ('localhost', '127.0.0.1', '::1');")

    # Get list of already existing databases:
    cursor.execute("SHOW DATABASES")
    databases = cursor.fetchall()
    existing_dbs = [database[0] for database in databases]
    for dbn in existing_dbs:
        if dbn == "test":
            print "removing test database"
            drop_db(cursor, "test")

    mysql_db_create()

    print "reloading privilege tables"
    cursor.execute("FLUSH PRIVILEGES;")
    db.commit()
    db.close()

def keystone():
    print "configuring keystone"

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/keystone/keystone.conf"))
    # config.set("DEFAULT", "verbose", "true") # XXX deprecated

    # for bootstrapping, it is removed after configured
    config.set("DEFAULT", "admin_token", SERVICE_TOKEN)

    # Set the server name for WSGI
    check_call(["/usr/sbin/svccfg", "-s", "keystone:default", "setprop", "config/servername",
        "=", KEYSTONE_NODE])

    service = "keystone"
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        if RABBITMQ_USE_SSL:
            config.set("oslo_messaging_rabbit", "kombu_ssl_ca_certs", SOL_CACERTS_FILE)
            #config.set("oslo_messaging_rabbit", "kombu_ssl_certfile", clientcert)
            #config.set("oslo_messaging_rabbit", "kombu_ssl_keyfile", clientkey)
            config.set("oslo_messaging_rabbit", "rabbit_hosts",
                    "%s:5671" % RABBIT_NODE)
            config.set("oslo_messaging_rabbit", "rabbit_use_ssl", "true")
        else:
            config.set("oslo_messaging_rabbit", "rabbit_hosts",
                    "%s:5672" % RABBIT_NODE)
        config.set("oslo_messaging_rabbit", "rabbit_userid", RABBITMQ_USER)
        config.set("oslo_messaging_rabbit", "rabbit_password", RABBITMQ_PASS)
        config.set("database", "connection",
                   "mysql://keystone:keystone-pass@%s/keystone?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
    else:
        config.set("oslo_messaging_rabbit", "rabbit_hosts",
                "%s:5672" % RABBIT_NODE)
        config.set("oslo_messaging_rabbit", "rabbit_userid", RABBITMQ_USER)
        config.set("oslo_messaging_rabbit", "rabbit_password", RABBITMQ_PASS)
        config.set("database", "connection",
                "mysql://keystone:keystone-pass@%s/keystone" % DB_NODE)
    with open("/etc/keystone/keystone.conf", "wb") as fh:
        config.write(fh)

    if USE_SSL:
        servercert = get_ssl_path(service, "servercert")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        # Keystone is using HTTP WSGI so we need to configure in SMF
        # which uses a stencil to build the Apache config file at:
        # /var/lib/keystone/keystone.httpd.conf
        svcname = "openstack/keystone:default"
        check_call(["/usr/sbin/svccfg", "-s", svcname, "setprop",
            "config/use_tls=true"])
        check_call(["/usr/sbin/svccfg", "-s", svcname, "setprop",
            "config/ssl_cert_file=%s" % servercert])
        check_call(["/usr/sbin/svccfg", "-s", svcname, "setprop",
            "config/ssl_cert_key_file=%s" % serverkey])
        check_call(["/usr/sbin/svccfg", "-s", svcname, "setprop",
            "config/ssl_ca_cert_file=%s" % SOL_CACERTS_FILE])

    print "enabling keystone"
    check_call(["/usr/sbin/svcadm", "refresh", "-s", "keystone"])
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "keystone"])

    # OIB v
    time.sleep(3)

    fscript = "keystone_data.sh"

    if USE_SSL:
        TLS_ENDPOINTS="true"
    else:
        TLS_ENDPOINTS="false"

    print "loading initial data"
    if USE_SSL:
        check_call(["/usr/bin/bash", fscript],
                   env={"TLS_ENDPOINTS": TLS_ENDPOINTS,
                        "OS_CACERT": SOL_CACERTS_FILE,
                        "ADMIN_USER": ADMIN_USER,
                        "ADMIN_PASSWORD": ADMIN_PASSWORD,
                        "SERVICE_PASSWORD": SERVICE_PASSWORD,
                        "DEFAULT_PROJECT": DEFAULT_PROJECT,
                        "SERVICE_PROJECT": SERVICE_PROJECT,
                        "REGION_NAME": REGION_NAME,
                        "CONTROLLER_PUBLIC_ADDRESS": CONTROLLER_NODE,
                        "CONTROLLER_ADMIN_ADDRESS": CONTROLLER_NODE,
                        "CONTROLLER_INTERNAL_ADDRESS": CONTROLLER_NODE,
                        "GLANCE_PUBLIC_ADDRESS": GLANCE_NODE,
                        "GLANCE_ADMIN_ADDRESS": GLANCE_NODE,
                        "GLANCE_INTERNAL_ADDRESS": GLANCE_NODE,
                        "CINDER_PUBLIC_ADDRESS": CINDER_NODE,
                        "CINDER_ADMIN_ADDRESS": CINDER_NODE,
                        "CINDER_INTERNAL_ADDRESS": CINDER_NODE,
                        "NEUTRON_PUBLIC_ADDRESS": NEUTRON_NODE,
                        "NEUTRON_ADMIN_ADDRESS": NEUTRON_NODE,
                        "NEUTRON_INTERNAL_ADDRESS": NEUTRON_NODE})
    else:
        check_call(["/usr/bin/bash", fscript],
                   env={"TLS_ENDPOINTS": TLS_ENDPOINTS,
                        "ADMIN_USER": ADMIN_USER,
                        "ADMIN_PASSWORD": ADMIN_PASSWORD,
                        "SERVICE_PASSWORD": SERVICE_PASSWORD,
                        "DEFAULT_PROJECT": DEFAULT_PROJECT,
                        "SERVICE_PROJECT": SERVICE_PROJECT,
                        "REGION_NAME": REGION_NAME,
                        "CONTROLLER_PUBLIC_ADDRESS": CONTROLLER_NODE,
                        "CONTROLLER_ADMIN_ADDRESS": CONTROLLER_NODE,
                        "CONTROLLER_INTERNAL_ADDRESS": CONTROLLER_NODE,
                        "GLANCE_PUBLIC_ADDRESS": GLANCE_NODE,
                        "GLANCE_ADMIN_ADDRESS": GLANCE_NODE,
                        "GLANCE_INTERNAL_ADDRESS": GLANCE_NODE,
                        "CINDER_PUBLIC_ADDRESS": CINDER_NODE,
                        "CINDER_ADMIN_ADDRESS": CINDER_NODE,
                        "CINDER_INTERNAL_ADDRESS": CINDER_NODE,
                        "NEUTRON_PUBLIC_ADDRESS": NEUTRON_NODE,
                        "NEUTRON_ADMIN_ADDRESS": NEUTRON_NODE,
                        "NEUTRON_INTERNAL_ADDRESS": NEUTRON_NODE})

    # We don't need the bootstrap token anymore
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/keystone/keystone.conf"))
    config.remove_option("DEFAULT", "admin_token")
    with open("/etc/keystone/keystone.conf", "wb") as fh:
        config.write(fh)

    print "restarting keystone"
    check_call(["/usr/sbin/svcadm", "restart", "-s", "keystone"])

    print "testing keystone"
    print "openstack user list"
    if USE_SSL:
        check_call(["/usr/bin/openstack", "user", "list"],
               env={"OS_AUTH_URL": SERVICE_ENDPOINT,
                    "OS_TENANT_NAME": DEFAULT_PROJECT,
                    "OS_USERNAME": ADMIN_USER,
                    "OS_PASSWORD": ADMIN_PASSWORD,
                    "OS_CACERT": SOL_CACERTS_FILE})
    else:
        check_call(["/usr/bin/openstack", "user", "list"],
               env={"OS_AUTH_URL": SERVICE_ENDPOINT,
                    "OS_TENANT_NAME": DEFAULT_PROJECT,
                    "OS_USERNAME": ADMIN_USER,
                    "OS_PASSWORD": ADMIN_PASSWORD})


GLANCE_PATH = "/%s" % GLANCE_DATASET
GLANCE_IMAGES = "%s/images/" % GLANCE_PATH
GLANCE_CACHE = "%s/image-cache/" % GLANCE_PATH

def get_os_release():
    p = Popen(["/usr/sbin/uname", "-r"], stdout=PIPE)
    output = p.communicate()[0]
    output = output.rstrip()
    return output

# Adds a UAR to the Glance image store.  Will check the UAR
# architecture and pass correct parameters.
def glance_add_image(image, name):
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_USERNAME": "glance",
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_USERNAME": "glance",
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_TENANT_NAME": SERVICE_PROJECT}


    # Determine the image arch
    cmd1 = ["/usr/sbin/archiveadm", "info", "-p", "%s" % image]
    cmd2 = ["/usr/bin/grep", "^archive"]

    if get_os_release() == "5.11":
        # S11 cut
        cmd3 = ["/usr/bin/cut", "-d", "|", "-f", "4"]
    else:
        cmd3 = ["/usr/bin/cut", "-d", "|", "-f", "5"]

    p1 = Popen(cmd1, stdout=PIPE)
    p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE)
    p3 = Popen(cmd3, stdin=p2.stdout, stdout=PIPE)
    output = p3.communicate()[0]
    output = output.rstrip()

    if output == "i386":
        imgarch = "x86_64"
    else:
        imgarch = "sparc64"

    check_call(["/usr/bin/openstack", "image", "create", "--container-format", "bare", "--disk-format", "raw",
        "--file", image, "--public", "--property", "architecture=%s" % imgarch, "--property",
        "hypervisor_type=solariszones", "--property", "vm_mode=solariszones", name], env=env)


# Add all the images in the directory to the Glance
# image store
def glance_add_images():
    print "Adding images to Glance store..."
    # Add all images in directory to Glance
    images = [f for f in listdir(GLANCE_IMAGE_SOURCE_DIR)
            if isfile(join(GLANCE_IMAGE_SOURCE_DIR, f))]

    for image in images:
        name = os.path.splitext(image)[0]
        glance_add_image(GLANCE_IMAGE_SOURCE_DIR + "/" + image, name)


# Fill in necessary information for -paste.ini to talk
# to Keystone
def cfg_paste_fill_in(config, service):
    if USE_SSL:
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("filter:authtoken", "paste.filter_factory",
                "keystonemiddleware.auth_token:filter_factory")
        config.set("filter:authtoken", "delay_auth_decision", "true")
        config.set("filter:authtoken", "auth_protocol", "https")
        config.set("filter:authtoken", "auth_uri", PUBLIC_ENDPOINT)
        config.set("filter:authtoken", "identity_uri", IDENTITY_URI)
        config.set("filter:authtoken", "admin_tenant_name", SERVICE_PROJECT)
        config.set("filter:authtoken", "admin_user", service)
        config.set("filter:authtoken", "admin_password", SERVICE_PASSWORD)
        config.set("filter:authtoken", "cafile", SOL_CACERTS_FILE)
        #config.set("filter:authtoken", "certfile", clientcert)
        #config.set("filter:authtoken", "keyfile", clientkey)
    else:
        config.set("filter:authtoken", "auth_uri", PUBLIC_ENDPOINT)
        config.set("filter:authtoken", "identity_uri", IDENTITY_URI)
        config.set("filter:authtoken", "admin_tenant_name", SERVICE_PROJECT)
        config.set("filter:authtoken", "admin_user", "glance")
        config.set("filter:authtoken", "admin_password", SERVICE_PASSWORD)
    config.set("filter:authtoken", "signing_dir",
            "/var/lib/%s/keystone-signing" % service)

# Fill in necessary information for .conf to talk to
# Keystone and RabbitMQ
def cfg_fill_in(config, service):
    if USE_SSL:
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("keystone_authtoken", "auth_version", "2.0")
        config.set("keystone_authtoken", "auth_protocol", "https")
        config.set("keystone_authtoken", "insecure", "false")
        config.set("keystone_authtoken", "auth_uri", PUBLIC_ENDPOINT)
        config.set("keystone_authtoken", "identity_uri", IDENTITY_URI)
        config.set("keystone_authtoken", "admin_tenant_name", SERVICE_PROJECT)
        config.set("keystone_authtoken", "admin_user", service)
        config.set("keystone_authtoken", "admin_password", SERVICE_PASSWORD)
        config.set("keystone_authtoken", "cafile", SOL_CACERTS_FILE)
        #config.set("keystone_authtoken", "certfile", clientcert)
        #config.set("keystone_authtoken", "keyfile", clientkey)
        if not config.has_section("oslo_messaging_rabbit"):
            config.add_section("oslo_messaging_rabbit")
        if RABBITMQ_USE_SSL:
            #config.set("oslo_messaging_rabbit", "kombu_ssl_certfile", clientcert)
            #config.set("oslo_messaging_rabbit", "kombu_ssl_keyfile", clientkey)
            config.set("oslo_messaging_rabbit", "rabbit_hosts",
                    "%s:5671"  % RABBIT_NODE)
            config.set("oslo_messaging_rabbit", "rabbit_use_ssl", "true")
            config.set("oslo_messaging_rabbit", "kombu_ssl_ca_certs", SOL_CACERTS_FILE)
        else:
            config.set("oslo_messaging_rabbit", "rabbit_hosts",
                    "%s:5672" % RABBIT_NODE)
        config.set("oslo_messaging_rabbit", "rabbit_userid", RABBITMQ_USER)
        config.set("oslo_messaging_rabbit", "rabbit_password", RABBITMQ_PASS)
    else:
        config.set("keystone_authtoken", "admin_tenant_name", SERVICE_PROJECT)
        config.set("keystone_authtoken", "admin_user", service)
        config.set("keystone_authtoken", "admin_password", SERVICE_PASSWORD)
        config.set("keystone_authtoken", "auth_uri", PUBLIC_ENDPOINT)
        config.set("keystone_authtoken", "identity_uri", IDENTITY_URI)
        if not config.has_section("oslo_messaging_rabbit"):
            config.add_section("oslo_messaging_rabbit")
        config.set("oslo_messaging_rabbit", "rabbit_hosts",
                "%s:5672" % RABBIT_NODE)
        config.set("oslo_messaging_rabbit", "rabbit_userid", RABBITMQ_USER)
        config.set("oslo_messaging_rabbit", "rabbit_password", RABBITMQ_PASS)

    # Use memcached for tokens
    config.set("keystone_authtoken", "memcached_servers", "localhost")

# This configurages the backend storage for Glance
def glance_fill_in_glance_store(config):
    if not config.has_section("glance_store"):
        config.add_section("glance_store")
    if GLANCE_STORE == "swift":
        config.set("glance_store", "default_store", "swift")
        config.remove_option("glance_store", "filesystem_store_datadir")
        config.set("glance_store", "stores", "glance.store.swift.Store")
        config.set("glance_store", "swift_store_auth_address", PUBLIC_ENDPOINT)
        config.set("glance_store", "swift_store_user",
                "%s:glance" % SERVICE_PROJECT)
        config.set("glance_store", "swift_store_key", SERVICE_PASSWORD)
        config.set("glance_store", "swift_store_create_container_on_put",
                "True")
        config.set("glance_store", "swift_enable_snet", "false")
        #config.set("glance_store", "swift_store_large_object_size", "5120")
        #config.set("glance_store", "swift_store_large_object_chunk_size", "200")
        if USE_SSL:
            # XXX glance lacks parameter to specify CA, so we use this as
            # a workaround for self-signed certs
            config.set("glance_store", "swift_store_auth_insecure", "true")
            #config.set("glance_store", "swift_store_auth_insecure", "false")
    elif GLANCE_STORE == "s3":
        config.set("glance_store", "default_store", "s3")
        config.remove_option("glance_store", "filesystem_store_datadir")
        config.set("glance_store", "stores", "glance.store.s3.Store")
        config.set("glance_store", "swift_store_auth_address", PUBLIC_ENDPOINT)
        config.set("glance_store", "swift_store_user",
                "%s:glance" % SERVICE_PROJECT)
        config.set("glance_store", "swift_store_key", SERVICE_PASSWORD)
        config.set("glance_store", "swift_store_create_container_on_put",
                "True")
        config.set("glance_store", "swift_enable_snet", "false")
        if USE_SSL:
            # XXX glance lacks parameter to specify CA, so we use this as
            # a workaround for self-signed certs
            config.set("glance_store", "swift_store_auth_insecure", "true")
            #config.set("glance_store", "swift_store_auth_insecure", "false")
            config.set("glance_store", "s3_store_host",
                    "https://%s:8080/v1.0/" % SWIFT_NODE)
        else:
            config.set("glance_store", "s3_store_host",
                    "http://%s:8080/v1.0/" % SWIFT_NODE)
        config.set("glance_store", "s3_store_access_key", "FILLIN")
        config.set("glance_store", "s3_store_secret_key", "FILLIN")
        config.set("glance_store", "s3_store_bucket", "glanceLOWERCASEACCESSCRED")
        config.set("glance_store", "s3_store_create_bucket_on_put", "True")
    elif GLANCE_STORE == "file":
        config.set("glance_store", "default_store", "file")
        config.set("glance_store", "filesystem_store_datadir", GLANCE_IMAGES)

# Configures Glance image service
def glance():
    print "configuring glance"

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/glance/glance-api.conf"))
    if GLANCE_STORE == "file":
        config.set("DEFAULT", "image_cache_dir", GLANCE_CACHE)
    else:
        # not required for other stores
        config.remove_option("DEFAULT", "filesystem_store_datadir")
        config.remove_option("DEFAULT", "image_cache_dir")

    # config.set("DEFAULT", "verbose", "true") # XXX deprecated
    service = "glance"
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #config.set("DEFAULT", "ca_file", ca)
        config.set("DEFAULT", "cert_file", servercert)
        config.set("DEFAULT", "key_file", serverkey)
        config.set("database", "connection",
                   "mysql://glance:glance-pass@%s/glance?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
        config.set("DEFAULT", "registry_client_protocol", "https")
        config.set("DEFAULT", "registry_client_ca_file", SOL_CACERTS_FILE)
    else:
        config.set("database", "connection",
                "mysql://glance:glance-pass@%s/glance" % DB_NODE)

    config.set("paste_deploy", "flavor", "keystone")
    cfg_fill_in(config, service)
    glance_fill_in_glance_store(config)
    with open("/etc/glance/glance-api.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/glance/glance-cache.conf"))
    config.set("DEFAULT", "metadata_encryption_key", NOVA_METADATA_SECRET)
    config.set("DEFAULT", "auth_url", PUBLIC_ENDPOINT)
    config.set("DEFAULT", "admin_tenant_name", SERVICE_PROJECT)
    config.set("DEFAULT", "admin_user", "glance")
    config.set("DEFAULT", "admin_password", SERVICE_PASSWORD)
    if USE_SSL:
        # Workaround because there doesn't appear a way to specify a
        # CA file for use with self-signed certs for use with Keystone
        # This CA is used for connecting to the registry server
        config.set("DEFAULT", "registry_client_insecure", "true")
        #config.set("DEFAULT", "registry_client_insecure", "false")
        config.set("DEFAULT", "registry_client_protocol", "https")
        config.set("DEFAULT", "registry_client_ca_file", SOL_CACERTS_FILE)
        config.set("DEFAULT", "registry_client_use_ssl", "true")
    if GLANCE_STORE == "file":
        config.set("DEFAULT", "image_cache_dir", GLANCE_CACHE)
    else:
        # not required for other stores
        config.remove_option("DEFAULT", "filesystem_store_datadir")
        config.remove_option("DEFAULT", "image_cache_dir")
    glance_fill_in_glance_store(config)
    with open("/etc/glance/glance-cache.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/glance/glance-registry.conf"))
    config.set("DEFAULT", "metadata_encryption_key", NOVA_METADATA_SECRET)
    cfg_fill_in(config, service)
    if USE_SSL:
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        config.set("DEFAULT", "cert_file", servercert)
        config.set("DEFAULT", "key_file", serverkey)
        config.set("database", "connection",
                   "mysql://glance:glance-pass@%s/glance?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
    else:
        config.set("database", "connection",
                "mysql://glance:glance-pass@%s/glance" % DB_NODE)
    config.set("paste_deploy", "flavor", "keystone")
    glance_fill_in_glance_store(config)
    with open("/etc/glance/glance-registry.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/glance/glance-api-paste.ini"))
    cfg_paste_fill_in(config, service)
    with open("/etc/glance/glance-api-paste.ini", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/glance/glance-registry-paste.ini"))
    cfg_paste_fill_in(config, service)
    with open("/etc/glance/glance-registry-paste.ini", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/glance/glance-scrubber.conf"))
    config.set("DEFAULT", "metadata_encryption_key", NOVA_METADATA_SECRET)
    config.set("DEFAULT", "daemon", "True")
    config.set("DEFAULT", "auth_url", PUBLIC_ENDPOINT)
    config.set("DEFAULT", "admin_tenant_name", SERVICE_PROJECT)
    config.set("DEFAULT", "admin_user", "glance")
    config.set("DEFAULT", "admin_password", SERVICE_PASSWORD)
    config.set("DEFAULT", "auth_strategy", "keystone")
    if USE_SSL:
        # Workaround because there doesn't appear a way to specify a
        # CA file for use with self-signed certs for use with Keystone
        # This CA is used for connecting to the registry server
        config.set("DEFAULT", "registry_client_insecure", "true")
        #config.set("DEFAULT", "registry_client_insecure", "false")
        config.set("DEFAULT", "registry_client_protocol", "https")
        config.set("DEFAULT", "registry_client_ca_file", SOL_CACERTS_FILE)
        config.set("DEFAULT", "registry_client_use_ssl", "true")

    glance_fill_in_glance_store(config)

    if not config.has_section("database"):
        config.add_section("database")
    if USE_SSL:
        config.set("database", "connection",
                   "mysql://glance:glance-pass@%s/glance?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
    else:
        config.set("database", "connection",
                "mysql://glance:glance-pass@%s/glance" % DB_NODE)
    with open("/etc/glance/glance-scrubber.conf", "wb") as fh:
        config.write(fh)

    if GLANCE_STORE == "file":
        print "Creating zfs dataset"
        # By default Glance images are compressed
        check_call(["/usr/sbin/zfs", "create", "-o",
                "compression=on", GLANCE_DATASET])
        check_call(["/usr/bin/chown", "glance:glance", GLANCE_PATH])


    check_call(["/usr/bin/mkdir", "-p", GLANCE_CACHE])
    check_call(["/usr/bin/chown", "glance:glance", GLANCE_CACHE])

    print "enabling glance-api, glance-registry, and glance-scrubber"

    check_call(["/usr/sbin/svcadm", "enable", "-rs", "glance-db",
            "glance-registry"])
    # OIB v
    time.sleep(2)

    # Pick up new SMF values
    check_call(["/usr/sbin/svcadm", "refresh", "glance-api:default"])

    if GLANCE_STORE == "file":
        # need the scrubber
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "glance-api:default",
                    "glance-db", "glance-registry", "glance-scrubber"])
    else:
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "glance-api:default",
            "glance-db", "glance-registry"])

    # OIB v
    time.sleep(4)

    print "testing glance"
    print "glance image-list:"
    if USE_SSL:
        check_call(["/usr/bin/openstack", "image", "list"],
                env={"OS_AUTH_URL": SERVICE_ENDPOINT,
                     "OS_PASSWORD": SERVICE_PASSWORD,
                     "OS_USERNAME": "glance",
                     "OS_CACERT": SOL_CACERTS_FILE,
                     "OS_TENANT_NAME": SERVICE_PROJECT})
    else:
        check_call(["/usr/bin/openstack", "image", "list"],
                env={"OS_AUTH_URL": SERVICE_ENDPOINT,
                     "OS_PASSWORD": SERVICE_PASSWORD,
                     "OS_USERNAME": "glance",
                     "OS_TENANT_NAME": SERVICE_PROJECT})

def cinder():
    print "configuring cinder"

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/cinder/cinder.conf"))
    #config.set("DEFAULT", "verbose", "true")

    # Set the server name for WSGI
    check_call(["/usr/sbin/svccfg", "-s", "cinder-api:default", "setprop",
            "config/servername", "=", CINDER_NODE])

    # v1 API deprecated
    config.set("DEFAULT", "enable_v1_api", "false")
    config.set("DEFAULT", "enable_v2_api", "true")
    config.set("DEFAULT", "enable_v3_api", "true")

    if USE_SSL:
        service = "cinder"
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("database", "connection",
                   "mysql://cinder:cinder-pass@%s/cinder?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
        # SMF service for WSGI TLS
        check_call(["/usr/sbin/svccfg", "-s", "cinder-api:default", "setprop",
                "config/ssl_cert_file", "=", servercert])
        check_call(["/usr/sbin/svccfg", "-s", "cinder-api:default", "setprop",
                "config/ssl_cert_key_file", "=", serverkey])
        check_call(["/usr/sbin/svccfg", "-s", "cinder-api:default", "setprop",
                "config/ssl_ca_cert_file", "=", SOL_CACERTS_FILE])
        check_call(["/usr/sbin/svccfg", "-s", "cinder-api:default", "setprop",
                "config/use_tls", "=", "true"])
        # Cinder Eventlet may have a bug reading these options
        config.set("ssl", "cert_file", servercert)
        config.set("ssl", "key_file", serverkey)
        config.set("DEFAULT", "glance_ca_certificates_file", SOL_CACERTS_FILE)
        config.set("DEFAULT", "driver_use_ssl", "true")
    else:
        config.set("database", "connection",
                "mysql://cinder:cinder-pass@%s/cinder" % DB_NODE)

    cfg_fill_in(config, "cinder")

    config.set("DEFAULT", "my_ip", socket.gethostbyname(DB_NODE))
    config.set("DEFAULT", "auth_strategy", "keystone")
    config.set("DEFAULT", "driver_use_ssl", "true")

    # Configure how Cinder stores the data

    # Configure for use with ZFSSA so it allocates iSCSI LUNs
    # on the compute node as each compute instance in launched
    if CINDER_STORE == "zfssaiscsi":
        config.set("DEFAULT", "volume_driver",
                 "cinder.volume.drivers.zfssa.zfssaiscsi.ZFSSAISCSIDriver")
        config.set("DEFAULT", "san_ip", ZFSSA_MGT_HOST)
        config.set("DEFAULT", "san_login", ZFSSA_CINDER_USER)
        config.set("DEFAULT", "san_password", ZFSSA_CINDER_PASSWORD)
        config.set("DEFAULT", "zfssa_pool", ZFSSA_POOL)
        config.set("DEFAULT", "zfssa_target_portal", ZFSSA_TARGET_PORTAL)
        config.set("DEFAULT", "zfssa_project", ZFSSA_PROJECT)
        config.set("DEFAULT", "zfssa_initiator", ZFSSA_INITIATOR)
        config.set("DEFAULT", "zfssa_target_group", ZFSSA_TARGET_GROUP)
        config.set("DEFAULT", "zfssa_initiator_group", ZFSSA_INIT_GROUP)
        config.set("DEFAULT", "zfssa_target_interfaces", ZFSSA_TARGET_INTFS)
    else:
        check_call(["/usr/sbin/zpool", "status", CINDER_ZPOOL])
        config.set("DEFAULT", "zfs_volume_base", CINDER_DATASET)

    if CINDER_STORE == "zfsiscsi":
        config.set("DEFAULT", "volume_driver",
                 "cinder.volume.drivers.solaris.zfs.ZFSISCSIDriver")

    config.set("DEFAULT", "scheduler_driver",
               "cinder.scheduler.filter_scheduler.FilterScheduler")
    config.set("DEFAULT", "san_is_local", "true")

    if USE_CEILOMETER:
        # http://docs.openstack.org/developer/ceilometer/install/development.html
        config.set("DEFAULT", "notification_driver", "messagingv2")
        # http://docs.openstack.org/developer/ceilometer/install/manual.html
        config.set("DEFAULT", "notification_driver",
          "oslo.messaging.notifier.Notifier")
        # default is openstack
        #config.set("DEFAULT", "control_exchange", "cinder")

    with open("/etc/cinder/cinder.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/cinder/api-paste.ini"))
    cfg_paste_fill_in(config, "cinder")
    with open("/etc/cinder/api-paste.ini", "wb") as fh:
        config.write(fh)

    if CINDER_STORE == "zfslocal":
        print "Creating encrypted dataset for cinder data"
        check_call(["/usr/bin/pktool", "genkey", "keystore=file",
                   "outkey=/root/cinderkey", "keytype=aes", "keylen=256"])
        if CINDER_COMPRESS_DATA:
            check_call(["/usr/sbin/zfs", "create", "-o",
                        "encryption=aes-256-ccm",
                        "-o", "keysource=raw,file:///root/cinderkey",
                        "-o", "compression=on", CINDER_DATASET])
        else:
            check_call(["/usr/sbin/zfs", "create", "-o",
                        "encryption=aes-256-ccm",
                        "-o", "keysource=raw,file:///root/cinderkey",
                        CINDER_DATASET])

    print "enabling cinder services"

    # Pick up new SMF values
    check_call(["/usr/sbin/svcadm", "refresh", "cinder-api:default"])

    if CINDER_STORE == "zfsiscsi" or CINDER_STORE == "zfssaiscsi":
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "cinder-api",
            "cinder-db", "cinder-backup", "cinder-scheduler",
            "cinder-volume:setup", "cinder-volume:default",
            "iscsi/target"])
    else:
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "cinder-api",
            "cinder-db", "cinder-backup", "cinder-scheduler",
            "cinder-volume:setup", "cinder-volume:default"])

    print "testing cinder"
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "cinder",
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "cinder",
             "OS_TENANT_NAME": SERVICE_PROJECT}

    print "openstack volume list"
    check_call(["/usr/bin/openstack", "volume", "list"], env=env)

def nova_common():
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/nova/nova.conf"))
    #config.set("DEFAULT", "verbose", "true") # XXX deprecated
    config.set("DEFAULT", "network_manager", "nova.network.manager.FlatManager")
    if NOVA_SLOW_KEYSTONE:
        # Increase timeout for keystone requests
        config.set("DEFAULT", "http_connect_timeout", "45")
    service = "nova"
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        # Certs for the server API endpoint
        #config.set("DEFAULT", "ssl_ca_file", ca)
        config.set("DEFAULT", "ssl_cert_file", servercert)
        config.set("DEFAULT", "ssl_key_file", serverkey)
        config.set("ssl", "cert_file", servercert)
        config.set("ssl", "key_file", serverkey)
        # novnc endpoint
        config.set("DEFAULT", "cert", servercert)
        config.set("DEFAULT", "key", serverkey)
        #config.set("DEFAULT", "ca_file", ca)
        config.set("DEFAULT", "enabled_ssl_apis", "osapi_compute,metadata")
        #config.set("DEFAULT", "keystone_ec2_url",
        #        "https://%s:5000/v2.0/ec2tokens" % KEYSTONE_NODE) # depr
        if not config.has_section("ssl"):
            config.add_section("ssl")
        config.set("ssl", "ca_file", SOL_CACERTS_FILE)
        #config.set("ssl", "cert_file", clientcert)
        #config.set("ssl", "key_file", clientkey)
        config.set("glance", "api_servers", "https://%s:9292" % GLANCE_NODE)
        config.set("glance", "api_insecure", "false")

        # S3
        #config.set("DEFAULT", "s3_host", MY_IP)
        config.set("DEFAULT", "s3_use_ssl", "true")

        # client side
        config.set("neutron", "insecure", "false")
        config.set("neutron", "url", "https://%s:9696" % NEUTRON_NODE)
        config.set("neutron", "cafile", SOL_CACERTS_FILE)
        #config.set("neutron", "certfile", clientcert)
        #config.set("neutron", "keyfile", clientkey)
        config.set("cinder", "insecure", "false")
        config.set("cinder", "url", "https://%s:8776" % CINDER_NODE)
        config.set("cinder", "cafile", SOL_CACERTS_FILE)
        #config.set("cinder", "certfile", clientcert)
        #config.set("cinder", "keyfile", clientkey)
        config.set("database", "connection",
                   "mysql://nova:nova-pass@%s/nova?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
        config.set("api_database", "connection",
                   "mysql://nova:nova-pass@%s/nova_api?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
    else:
        #config.set("DEFAULT", "keystone_ec2_url",
        #        "http://%s:5000/v2.0/ec2tokens" % KEYSTONE_NODE)
        config.set("database", "connection",
                "mysql://nova:nova-pass@%s/nova" % DB_NODE)
        config.set("api_database", "connection",
                "mysql://nova:nova-pass@%s/nova_api" % DB_NODE)
        config.set("neutron", "url", "http://%s:9696" % NEUTRON_NODE)
        config.set("glance", "api_servers", "http://%s:9292" % GLANCE_NODE)
        config.set("cinder", "url", "http://%s:8776" % CINDER_NODE)

    config.set("neutron", "auth_type", "v2password")
    #config.set("neutron", "auth_url", AUTH_URL)
    config.set("neutron", "auth_url", PUBLIC_ENDPOINT)
    config.set("neutron", "tenant_name", SERVICE_PROJECT)
    # XXX deprecation keeps switching back and forth on this param
    #config.set("neutron", "user-name", "neutron") # depr user-name
    config.set("neutron", "username", "neutron") # depr user-name
    # config.remove_option("neutron", "username")
    # vv needed for current bits
    #config.set("neutron", "username", "neutron") # XX depr user-name
    config.set("neutron", "password", SERVICE_PASSWORD)
    config.set("cinder", "auth_url", AUTH_URL)
    config.set("cinder", "tenant_name", SERVICE_PROJECT)
    config.set("cinder", "username", "cinder")
    config.set("cinder", "password", SERVICE_PASSWORD)
    # Ironic lacks a TLS endpoint at the moment
    config.set("ironic", "api_endpoint", "http://%s:6385/v2" % IRONIC_NODE)
    config.set("ironic", "admin_username", "ironic")
    config.set("ironic", "admin_password", SERVICE_PASSWORD)
    config.set("ironic", "admin_tenant_name", SERVICE_PROJECT)
    config.set("ironic", "admin_url", SERVICE_ENDPOINT)
    config.set("DEFAULT", "auth_strategy", "keystone")
    config.set("DEFAULT", "rpc_backend", "rabbit")
    config.set("DEFAULT", "firewall_driver",
               "nova.virt.firewall.NoopFirewallDriver")
    config.set("neutron", "auth_strategy", "keystone")
    config.set("DEFAULT", "use_neutron", "true")
    #config.set("DEFAULT", "verbose", "True")
    config.set("DEFAULT", "my_ip", MY_IP)

    config.set("neutron", "region_name", REGION_NAME)
    config.set("neutron", "timeout", "30")
    config.set("neutron", "auth_strategy", "keystone")
    #config.set("neutron", "default_tenant_id", "default")
    config.set("neutron", "service_metadata_proxy", "True")
    config.set("neutron", "metadata_proxy_shared_secret", NOVA_METADATA_SECRET)

    cfg_fill_in(config, "nova")

    # Turn on Nova metering notifications
    if USE_CEILOMETER:
        # http://docs.openstack.org/developer/ceilometer/install/development.html
        config.set("DEFAULT", "instance_usage_audit", "true")
        # http://docs.openstack.org/developer/ceilometer/install/manual.html
        config.set("DEFAULT", "instance_usage_audit", "true")
        config.set("DEFAULT", "instance_usage_audit_period", "hour")
        config.set("DEFAULT", "notify_on_change_state", "vm_and_task_state")
        config.set("DEFAULT", "notification_driver",
            "oslo.messaging.notifier.Notifier")
        # http://docs.openstack.org/admin-guide-cloud/content/section_telemetry-compute-meters.html
        config.set("DEFAULT", "compute_monitors", "ComputeDriverCPUMonitor")

    with open("/etc/nova/nova.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/nova/api-paste.ini"))
    cfg_paste_fill_in(config, "nova")
    with open("/etc/nova/api-paste.ini", "wb") as fh:
        config.write(fh)

def nova_controller_conf():
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/nova/nova.conf"))
    # Set VNC console configuration
    proxy_port = "6080"
    config.set("vnc", "novncproxy_port", proxy_port)
    config.set("vnc", "novncproxy_host", "0.0.0.0")
    if False:
        if USE_SSL:
            config.set("DEFAULT", "novncproxy_base_url",
                       "https://" + NOVA_NODE
                         + ":" + proxy_port + "/vnc_auto.html")
        else:
            config.set("DEFAULT", "novncproxy_base_url",
                       "http://" + NOVA_NODE
                         + ":" + proxy_port + "/vnc_auto.html")

    # get the number of CPUs so we can throttle down the requests made against
    # rabbitmq
    p = Popen(["/usr/sbin/psrinfo", "-p"], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    workers = out.strip()
    config.set("DEFAULT", "metadata_workers", workers)
    config.set("DEFAULT", "osapi_compute_workers", workers)
    config.set("DEFAULT", "ec2_workers", workers)
    config.set("conductor", "workers", workers)
    with open("/etc/nova/nova.conf", "wb") as fh:
        config.write(fh)

    print "enabling nova services"
    check_call(["/usr/sbin/svcadm", "enable", "-rs",  "nova-conductor",
                "nova-api-osapi-compute", "nova-scheduler",
                "nova-cert", "nova-api-metadata", "nova-novncproxy"])

    # OIB v consoleauth needs nova_api db created above. Dependency timing issue  XXX
    time.sleep(4)

    check_call(["/usr/sbin/svcadm", "enable", "-rs",  "nova-consoleauth"])

    print "testing nova"
    print "nova endpoints:"
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "nova",
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "nova",
             "OS_TENANT_NAME": SERVICE_PROJECT}

    check_call(["/usr/bin/openstack", "endpoint", "list"], env=env)

    print "nova list:"
    check_call(["/usr/bin/openstack", "server", "list"], env=env)

def nova_compute_conf():
    # Set VNC console configuration
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/nova/nova.conf"))
    proxy_port = "6080"
    #config.set("DEFAULT", "vnc_enabled", "true") # depr XXX
    config.set("vnc", "enabled", "true") # depr XXX
    #config.set("DEFAULT", "vncserver_listen", "0.0.0.0")
    config.set("vnc", "vncserver_listen", "0.0.0.0")
    if not SINGLE_NODE:
        config.set("DEFAULT", "vncserver_proxyclient_address", MY_IP)
    if USE_SSL:
        config.set("DEFAULT", "novncproxy_base_url",
                   "https://" + NOVA_NODE
                     + ":" + proxy_port + "/vnc_auto.html")
    else:
        config.set("DEFAULT", "novncproxy_base_url",
                   "http://" + NOVA_NODE
                     + ":" + proxy_port + "/vnc_auto.html")
    with open("/etc/nova/nova.conf", "wb") as fh:
        config.write(fh)

    print "enabling nova and RAD services"
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "rad:remote",
                "kz-migr", "nova-compute"])

    print "testing nova"
    print "nova endpoints:"
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "nova",
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "nova",
             "OS_TENANT_NAME": SERVICE_PROJECT}

    check_call(["/usr/bin/openstack", "endpoint", "list"], env=env)

    print "nova list:"
    check_call(["/usr/bin/openstack", "server", "list"], env=env)

def nova_compute():
    nova_common()
    nova_compute_conf()

def nova_controller():
    print "configuring nova"
    nova_common()
    nova_controller_conf()

def nova_single_node():
    print "configuring nova"
    nova_common()
    nova_controller_conf()
    nova_compute_conf()
    check_call(["/usr/sbin/svcadm", "restart", "-s", "nova-novncproxy",
                "kz-migr"])

def neutron_networking():
    print "Setting up l3-agent..."
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "neutron",
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "neutron",
             "OS_TENANT_NAME": SERVICE_PROJECT}

    # Create a router
    p = Popen(["/usr/bin/openstack", "router", "create", NEUTRON_ROUTER_NAME], env=env,
              stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        raise RuntimeError("openstack router create failed: %s" %  err)

    # get the id of the router
    for line in out.splitlines():
        try:
            if line.split()[1] == 'id':
                router_uuid = line.split()[3]
                break
        except IndexError:
            continue
    else:
        raise RuntimeError("Unable to get the UUID for the router")

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/neutron/l3_agent.ini"))
    config.set("DEFAULT", "auth_url", PUBLIC_ENDPOINT)
    config.set("DEFAULT", "admin_tenant_name", SERVICE_PROJECT)
    config.set("DEFAULT", "admin_user", "neutron")
    config.set("DEFAULT", "admin_password", SERVICE_PASSWORD)
    if USE_SSL:
        config.set("DEFAULT", "auth_ca_cert", SOL_CACERTS_FILE)
        config.set("DEFAULT", "cafile", SOL_CACERTS_FILE)
    config.set("DEFAULT", "interface_driver",
               "neutron.agent.solaris.interface.OVSInterfaceDriver")
    config.set("DEFAULT", "ovs_integration_bridge", "br_int0")
    config.set("DEFAULT", "external_network_bridge", "br_ex0")
    config.set("DEFAULT", "router_id", router_uuid)
    config.set("DEFAULT", "enable_metadata_proxy", "True")
    if L3_AGENT_FORWARD_BETWEEEN_TENANTS:
        config.set("DEFAULT", "allow_forwarding_between_networks", "true")
    with open("/etc/neutron/l3_agent.ini", "wb") as fh:
        config.write(fh)

    # enable neutron-l3-agent
    print "enabling neutron l3 agent"
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "neutron-l3-agent"])

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/neutron/metadata_agent.ini"))
    config.set("DEFAULT", "metadata_proxy_shared_secret", NOVA_METADATA_SECRET)
    with open("/etc/neutron/metadata_agent.ini", "wb") as fh:
        config.write(fh)

    print "testing neutron"
    check_call(["/usr/bin/openstack", "router", "show", NEUTRON_ROUTER_NAME], env=env)

    print "Create an External network"
    if EXT_NETWORK_TYPE == "flat":
        check_call(["/usr/bin/neutron", "net-create", "--router:external",
                   "--provider:physical_network", "flatnet",
                   "--provider:network_type=%s" % EXT_NETWORK_TYPE,
                   EXT_NETWORK_NAME], env=env)
    else:
        check_call(["/usr/bin/neutron", "net-create", "--router:external",
                   "--provider:physical_network", "extnet",
                   "--provider:network_type=%s" % EXT_NETWORK_TYPE,
                   "--provider:segmentation_id=%s" % EXT_NETWORK_TAG,
                   EXT_NETWORK_NAME], env=env)

    print "Assign a subnet that is routable from external world"
    if EXT_NETWORK_NO_FLOAT_IP:
        check_call(["/usr/bin/neutron", "subnet-create",
                   "--name", "%s_subnet" % EXT_NETWORK_NAME,
                   "--disable-dhcp", "--gateway", EXT_NETWORK_GATEWAY,
                   EXT_NETWORK_NAME, EXT_NETWORK_ADDR,
                   "--allocation-pool", "start=%s,end=%s"
                     % (EXT_NETWORK_SNAT_IP, EXT_NETWORK_SNAT_IP)],
                   env=env)
    else:
        check_call(["/usr/bin/neutron", "subnet-create",
                   "--name", "%s_subnet" % EXT_NETWORK_NAME,
                   "--disable-dhcp", "--gateway", EXT_NETWORK_GATEWAY,
                   EXT_NETWORK_NAME, EXT_NETWORK_ADDR,
                   "--allocation-pool", "start=%s,end=%s"
                     % (EXT_NETWORK_STARTIP, EXT_NETWORK_STOPIP)],
                   env=env)

    service_uuid = get_tenant_uuid(SERVICE_PROJECT, env)

    print "Set subnet as the gateway for cloud router"
    check_call(["/usr/bin/neutron", "router-gateway-set", NEUTRON_ROUTER_NAME,
               EXT_NETWORK_NAME], env=env)

    for user,pw,tenant,addr,floatingips,allocfips in TENANT_NET_LIST:
        # create the tenant
        check_call(["/usr/bin/openstack", "project", "create", tenant], env=env)
        check_call(["/usr/bin/openstack", "user", "create", user, "--project",
               tenant, "--password", pw], env=env)
        check_call(["/usr/bin/openstack", "role", "add", "--user", user,
                       "--project", tenant, "admin"], env=env)

        # Tenant scoping, use tenant username
        if USE_SSL:
            envt={"OS_USERNAME": user,
                  "OS_PASSWORD": ADMIN_PASSWORD,
                  "OS_CACERT": SOL_CACERTS_FILE,
                  "OS_AUTH_URL": SERVICE_ENDPOINT,
                  "OS_TENANT_NAME": tenant}
        else:
            envt={"OS_USERNAME": user,
                  "OS_PASSWORD": ADMIN_PASSWORD,
                  "OS_AUTH_URL": SERVICE_ENDPOINT,
                  "OS_TENANT_NAME": tenant}

        tenant_uuid = get_tenant_uuid(tenant, env)

        # If VLAN or VXLAN TAG is available it is automatically assigned from range
        print "Creating internal network for %s tenant" % tenant
        check_call(["/usr/bin/neutron", "net-create", "--tenant-id", tenant_uuid,
                   "%s_internal" % tenant], env=envt)

        print "Creating internal subnet for %s tenant" % tenant
        p = Popen(["/usr/bin/neutron", "subnet-create", "--tenant-id", tenant_uuid,
                  "--dns-nameserver", EXT_NETWORK_DNS,
                  "%s_internal" % tenant, addr],
                   env=envt, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            raise RuntimeError("neutron subnet-create failed: %s" %  err)

        # get the id of the subnet
        for line in out.splitlines():
            try:
                if line.split()[1] == 'id':
                    subnet_uuid = line.split()[3]
                    break
            except IndexError:
                continue
        else:
            raise RuntimeError("Unable to get the UUID for the net")

        print "add interface to internal subnet"
        check_call(["/usr/bin/neutron", "router-interface-add", NEUTRON_ROUTER_NAME,
                   subnet_uuid], env=env)

        print "create floating ips for tenant %s" % tenant
        check_call(["/usr/bin/neutron", "quota-update", "--tenant-id", tenant_uuid,
                   "--floatingip", str(floatingips)], env=envt)

        for i in range(0, allocfips):
            check_call(["/usr/bin/neutron", "floatingip-create", "--tenant-id",
                       tenant_uuid, EXT_NETWORK_NAME], env=envt)


# SSH for Ironic
def create_pubkey(user):
    # look for ssh keys for the user
    sshdir = os.path.join(user.pw_dir, ".ssh")
    if not os.path.exists(sshdir):
        os.mkdir(sshdir)

    print "setting %s/.ssh/config" % user.pw_dir
    ssh_config = "Host *\n\tStrictHostKeyChecking no\n"
    ssh_config_path = os.path.join(user.pw_dir, ".ssh", "config")
    with open(ssh_config_path, "w") as fh:
        fh.write(ssh_config)
    os.chmod(ssh_config_path, 0600)

    if not [f for f in os.listdir(sshdir) if f.endswith("rsa.pub")]:
        key = RSA.gen_key(2048, 65337)
        key.save_key(os.path.join(sshdir, "id_rsa"),
                     cipher=None)
        os.chmod(os.path.join(sshdir, "id_rsa"), 0600)
        p = Popen(["/usr/bin/ssh-keygen", "-y", "-f",
                   os.path.join(sshdir, "id_rsa")], stdout=PIPE, stderr=PIPE)
        pubkey, err = p.communicate()
        owner = "%s:%s" % (user.pw_name, grp.getgrgid(user.pw_gid).gr_name)
        check_call(["/usr/bin/chown", "-R", owner, sshdir])

        # add comment to end
        pubkey = pubkey.strip('\n')
        pubkey = "%s %s@%s\n" % (pubkey, user.pw_name, MY_NAME)
    else:
        with open(os.path.join(sshdir, "id_rsa.pub"), "r+") as fh:
            pubkey = fh.read()

    return pubkey

def create_etherstub():
    # Create an intermediate etherstub for the traffic to allow correct SNAT
    try:
        check_call(["/usr/sbin/dladm", "show-etherstub", INT_UPLINK_PORT], stdout=PIPE,
                   stderr=PIPE)
    except CalledProcessError:
        try:
            check_call(["/usr/sbin/dladm", "create-etherstub", INT_UPLINK_PORT])
        except CalledProcessError:
            raise RuntimeError("Unable to create etherstub")

def add_ovs_bridge(bridge_name, delete=True):
    try:
        if delete:
            check_call(['/usr/sbin/ovs-vsctl', '--', '--if-exists', 'del-br',
                    bridge_name])
        check_call(['/usr/sbin/ovs-vsctl', '--', '--may-exist', 'add-br',
                    bridge_name])
    except CalledProcessError as err:
        sys.exit("failed to create %s ovs bridge: %s" % (bridge_name, err))


def add_ovs_bridge_port(bridge_name, port_name):
    try:
        check_call(['/usr/sbin/ovs-vsctl', 'add-port', bridge_name, port_name])
    except CalledProcessError as err:
        sys.exit("failed to add port %s to bridge %s" % (port_name, bridge_name))

def get_default_gateways():
    def_gws = set()
    routes = check_output(['/usr/bin/pfexec', '/usr/bin/netstat',
                           '-arn']).splitlines()
    for route in routes:
        route = route.strip()
        elems = route.split()
        if elems and elems[0] == 'default':
            def_gws.add(elems[1])
    return def_gws

def add_uplink_to_br(uplink, bridge):
    def add_ips_and_gws_to_port(port):
        if ips:
            check_call(['/usr/bin/pfexec', '/usr/sbin/ipadm', 'create-ip',
                        port], stdout=PIPE)
        aconf_configured = False
        for ip in ips:
            msg = "Adding IP %s to %s" % (ip, port)
            print msg
            addrtype_addr = ip.split(':')
            addrtype, addr = addrtype_addr[0], addrtype_addr[1]
            if addrtype == 'static':
                check_call(['/usr/bin/pfexec', '/usr/sbin/ipadm',
                            'create-addr', '-T',  addrtype, '-a', addr, port],
                           stdout=PIPE)
            elif addrtype == 'addrconf':
                if not aconf_configured:
                    check_call(['/usr/bin/pfexec', '/usr/sbin/ipadm',
                                'create-addr', '-T', addrtype, port],
                               stdout=PIPE)
                    aconf_configured = True
            else:
                check_call(['/usr/bin/pfexec', '/usr/sbin/ipadm',
                            'create-addr', '-T', addrtype, port], stdout=PIPE)
        new_gateways = get_default_gateways()
        removed_gateways = old_gateways - new_gateways
        for gw in removed_gateways:
            # simple check for IPv6 address
            if ':' in gw:
                continue
            msg = "Adding default gateway %s" % gw
            print msg
            check_call(['/usr/bin/pfexec', '/usr/sbin/route', 'add', 'default',
                        gw], stdout=PIPE)

    msg = "Migrating %s link to OVS bridge: %s" % (uplink, bridge)
    print msg

    # Store IP and gateway info
    ips = []
    old_gateways = get_default_gateways()
    try:
        ips = check_output(['/usr/bin/pfexec', '/usr/sbin/ipadm', 'show-addr',
                            '-po', 'type,addr',
                            uplink], stderr=PIPE).splitlines()
        check_call(['/usr/bin/pfexec', '/usr/sbin/ipadm', 'delete-ip',
                    uplink], stdout=PIPE, stderr=PIPE)
    except CalledProcessError as err:
        pass

    try:
        check_call(['/usr/bin/pfexec', '/usr/sbin/dladm', 'set-linkprop', '-p',
                    'openvswitch=on', uplink], stdout=PIPE, stderr=PIPE)
    except CalledProcessError as err:
        msg = """Failed to set openvswitch property=on for %s - link is busy.
        Follow the below steps to migrate link to OVS bridge manually.
        1. Remove any flows, IP etc. so that link is unused.
        2. dladm set-linkprop -p openvswitch=on %s
        3. ovs-vsctl -- --may-exist add-port %s %s
        4. Replumb IPs, if existed before on %s, on %s.""" % \
            (uplink, uplink, bridge, uplink, uplink, bridge)
        print msg
    # add uplink to bridge
    check_call(['/usr/bin/pfexec', '/usr/sbin/ovs-vsctl', '--', '--may-exist',
                'add-port', bridge, uplink])
    try:
        add_ips_and_gws_to_port(bridge)
    except CalledProcessError as err:
        msg = """Failed to configure the IPs(%s) on br_ex0 VNIC. Manually
        configure the IPs and set default gateway""" % ips
        print msg


def neutron_conf_ovs():
    print "configuring OVS..."

    # start openvswitch and ovsdb service
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "vswitch-server",
                "ovsdb-server"])

    check_call(["/usr/sbin/ovs-appctl", "vlog/set", "file:dpif_solaris:dbg"])
    check_call(["/usr/sbin/ovs-appctl", "vlog/set", "file:netdev_solaris:dbg"])

    # set openvswitch property to on
    p = Popen(["/usr/sbin/dladm", "show-linkprop", "-co", "value",
               "-p", "openvswitch", INT_UPLINK_PORT], stdout=PIPE, stderr=PIPE)
    value, err = p.communicate()
    if value.strip() == "off":
        check_call(["/usr/sbin/dladm", "set-linkprop", "-p", "openvswitch=on",
                    INT_UPLINK_PORT])

    # create integration bridge
    add_ovs_bridge('br_int0')
    add_ovs_bridge_port('br_int0', INT_UPLINK_PORT)

    # create external bridge
    add_ovs_bridge('br_ex0', delete=False)
    try:
        check_call(['/usr/sbin/ovs-vsctl', 'br-set-external-id', 'br_ex0',
                    'bridge-id', 'br_ex0'])
    except CalledProcessError as err:
        sys.exit("failed to set bridge-id for br_ex0")

    # The dance
    add_uplink_to_br(EXT_UPLINK_PORT, "br_ex0")

    # set Other config information
    p = Popen(["/usr/sbin/ovs-vsctl", "get", "Open_vSwitch", ".", "_uuid"],
              stdout=PIPE, stderr=PIPE)
    uuid, err = p.communicate()
    check_call(["/usr/sbin/ovs-vsctl", "set", "Open_vSwitch", uuid.strip(),
                "other_config:bridge_mappings=physnet1:%s,"
                "extnet:%s,flatnet:%s" % (INT_UPLINK_PORT, EXT_UPLINK_PORT,
                        EXT_UPLINK_PORT)])

def neutron():
    if SINGLE_NODE:
        create_etherstub()

    neutron_conf_ovs()

    # Enable forwarding
    check_call(['/usr/sbin/ipadm', 'set-prop', '-p', 'forwarding=on', 'ipv4'])
    check_call(['/usr/sbin/ipadm', 'set-prop', '-p', 'forwarding=on', 'ipv6'])

    print "configuring neutron"
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/neutron/neutron.conf"))
    #config.set("DEFAULT", "verbose", "true") # depr XXX
    config.set("DEFAULT", "core_plugin", "ml2")
    config.set("DEFAULT", "service_plugins", "router")
    #config.set("DEFAULT", "allow_overlapping_ips", "False")
    config.set("DEFAULT", "allow_overlapping_ips", "true")
    config.set("DEFAULT", "auth_strategy", "keystone")
    config.set("DEFAULT", "notify_nova_on_port_status_changes", "true")
    config.set("DEFAULT", "notify_nova_on_port_data_changes", "true")
    service = "neutron"
    if not config.has_section("database"):
        config.add_section("database")
    if not config.has_section("nova"):
        config.add_section("nova")
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("DEFAULT", "use_ssl", "true")
        config.set("ssl", "cert_file", servercert)
        config.set("ssl", "key_file", serverkey)
        # Depr vv XXX
        #config.set("DEFAULT", "ssl_cert_file", servercert)
        #config.set("DEFAULT", "ssl_key_file", serverkey)

        # v can use v2 as well
        config.set("DEFAULT", "nova_url",
                "https://%s:8774/v3" % NOVA_METADATA_NODE)
        config.set("nova", "cafile", SOL_CACERTS_FILE)
        #config.set("nova", "certfile", clientcert)
        #config.set("nova", "keyfile", clientkey)
        config.set("nova", "insecure", "false")
        config.set("database", "connection",
                   "mysql://neutron:neutron-pass@%s/neutron?ssl_ca=%s" \
                           % (DB_NODE, SOL_CACERTS_FILE))
    else:
        config.set("DEFAULT", "nova_url",
                "http://%s:8774/v3" % NOVA_METADATA_NODE)
                #"http://%s:8774/v2" % NOVA_METADATA_NODE)
        config.set("database", "connection",
                "mysql://neutron:neutron-pass@%s/neutron" % DB_NODE)

    #config.set("nova", "auth_url", AUTH_URL)
    config.set("nova", "auth_url", PUBLIC_ENDPOINT)
    config.set("nova", "region_name", REGION_NAME)
    config.set("nova", "project_name", SERVICE_PROJECT)
    config.set("nova", "tenant_name", SERVICE_PROJECT)
    config.set("nova", "user-name", "nova")
    #config.set("nova", "username", "nova")  #depr
    config.remove_option("nova", "username")
    config.set("nova", "password", SERVICE_PASSWORD)
    config.set("nova", "auth_type", "v2password")
    cfg_fill_in(config, "neutron")
    # config.set("nova", "auth_plugin", "password") # depr
    with open("/etc/neutron/neutron.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.ConfigParser()
    config.readfp(open("/etc/neutron/plugins/ml2/ml2_conf.ini"))
    config.set("ml2", "tenant_network_types", INT_L2_LAN_TYPE)
    config.set("ml2_type_flat", "flat_networks", "flatnet")
    intnet_range = INT_L2_TAG_RANGE.replace('-',':')
    extnet_range = "%s:%s" % (EXT_NETWORK_TAG, EXT_NETWORK_TAG)
    if INT_L2_LAN_TYPE == "vlan":
        config.set("ml2_type_vlan", "network_vlan_ranges",
                   "physnet1:%s,extnet:%s" % (intnet_range, extnet_range))
    elif INT_L2_LAN_TYPE == "vxlan":
        config.set("ml2_type_vxlan", "vni_ranges",
                   "physnet1:%s,extnet:%s" % (intnet_range, extnet_range))
    else:
        raise ValueError('Specify value vlan or vxlan')
    with open("/etc/neutron/plugins/ml2/ml2_conf.ini", "wb") as fh:
        config.write(fh)

    config = iniparse.ConfigParser()
    config.readfp(open("/etc/neutron/plugins/ml2/openvswitch_agent.ini"))
    #config.set("DEFAULT", "verbose", "true") # depr XXX
    config.set("ovs", "integration_bridge", "br_int0")
    if EXT_NETWORK_TYPE == "flat":
        config.set("ovs", "bridge_mappings", "physnet1:%s,flatnet:%s" % (INT_UPLINK_PORT, EXT_UPLINK_PORT))
    else:
        config.set("ovs", "bridge_mappings", "physnet1:%s,extnet:%s" % (INT_UPLINK_PORT, EXT_UPLINK_PORT))

    config.set("agent", "root_helper", "")
    with open("/etc/neutron/plugins/ml2/openvswitch_agent.ini", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/neutron/metadata_agent.ini"))
    config.set("DEFAULT", "auth_url", PUBLIC_ENDPOINT)
    config.set("DEFAULT", "admin_tenant_name", SERVICE_PROJECT)
    config.set("DEFAULT", "admin_user", "neutron")
    config.set("DEFAULT", "admin_password", SERVICE_PASSWORD)
    if USE_SSL:
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("DEFAULT", "auth_ca_cert", SOL_CACERTS_FILE)
        config.set("DEFAULT", "nova_url",
                "https://%s:8774/v3" % NOVA_METADATA_NODE)
                #"https://%s:8774/v2.0" % NOVA_METADATA_NODE)
        #config.set("DEFAULT", "nova_ca_certificates_file", ca)
        if not config.has_section("nova"):
            config.add_section("nova")
        config.set("nova", "insecure", "false")
        config.set("DEFAULT", "nova_metadata_protocol", "https")
        config.set("DEFAULT", "nova_metadata_insecure", "false")
        #config.set("DEFAULT", "nova_client_cert", clientcert)
        #config.set("DEFAULT", "nova_client_priv_key", clientkey)
        config.set("DEFAULT", "nova_auth_ca_cert", SOL_CACERTS_FILE)
        #config.set("DEFAULT", "nova_metadata_ip", "127.0.0.1")
        #config.set("DEFAULT", "nova_metadata_port", "8775")
    else:
        config.set("DEFAULT", "nova_url",
                "http://%s:8774/v3" % NOVA_METADATA_NODE)
                #"http://%s:8774/v2" % NOVA_METADATA_NODE)
    config.set("DEFAULT", "nova_admin_username", "nova")
    config.set("DEFAULT", "nova_admin_password", SERVICE_PASSWORD)
    config.set("DEFAULT", "nova_admin_tenant_name", SERVICE_PROJECT)
    config.set("DEFAULT", "nova_admin_auth_url", AUTH_URL)
    config.set("DEFAULT", "nova_metadata_ip", NOVA_METADATA_NODE)
    config.set("DEFAULT", "nova_metadata_port", "8775")
    config.set("DEFAULT", "metadata_proxy_shared_secret", NOVA_METADATA_SECRET)
    with open("/etc/neutron/metadata_agent.ini", "wb") as fh:
        config.write(fh)
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/neutron/api-paste.ini"))
    cfg_paste_fill_in(config, service)
    with open("/etc/neutron/api-paste.ini", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/neutron/dhcp_agent.ini"))
    config.set("DEFAULT", "interface_driver",
               "neutron.agent.solaris.interface.OVSInterfaceDriver")
    config.set("DEFAULT", "ovs_integration_bridge", "br_int0")
    with open("/etc/neutron/dhcp_agent.ini", "wb") as fh:
        config.write(fh)

    # Enable the firewall
    if get_os_release() == "5.11":
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "ipfilter"])
    else:
        with open("/etc/firewall/pf.conf", "w+") as fh:
            fh.write('\nanchor \"_auto/*\"\n')
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "firewall"])

    # OIB v
    time.sleep(2)

    # add ML2 related databases
    print "creating ML2 tables"
    check_call(["/usr/bin/neutron-db-manage", "--config-file",
                "/etc/neutron/neutron.conf", "--config-file",
                "/etc/neutron/plugins/ml2/ml2_conf.ini", "upgrade", "head"],
                stdout=PIPE, stderr=PIPE)

    print "enabling neutron services"
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "rad:remote"])
    # OIB v XXX check
    time.sleep(3)
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "neutron-server"])
    # OIB v XXX check
    time.sleep(3)

    check_call(["/usr/sbin/svcadm", "enable", "-rs", "neutron-openvswitch-agent"])
    time.sleep(3)

    # XXX this should be able to start with dependencies below, however there
    # is a timing issue where openvswitch agent isn't fully up before dhcp-agent
    # requests from it
    check_call(["/usr/sbin/svcadm", "enable", "-rs",
        "neutron-dhcp-agent", "neutron-metadata-agent"])

    # OIB v XXX check
    time.sleep(2)

    print "testing neutron"
    print "neutron networks:"
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "neutron",
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "neutron",
             "OS_TENANT_NAME": SERVICE_PROJECT}

    check_call(["/usr/bin/openstack", "network", "list"], env=env)

def get_tenant_uuid(tenant_name, env):
    p = Popen(["/usr/bin/openstack", "project", "show", tenant_name], env=env,
              stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        raise RuntimeError("keystone tenant-get failed")

    # get the id of the tenant
    for line in out.splitlines():
        try:
            if line.split()[1] == 'id':
                uuid = line.split()[3]
                break
        except IndexError:
            continue
    else:
        raise RuntimeError("Unable to get the UUID for the tenant")

    return uuid

import tempfile
# Changes PARAM=VALUE in a config file
def cfg_file_change_param(ifile, param, newval):
    cmd = ["/usr/bin/gsed",
        's;^[#]*\(' + param + '* = *\)\(.*\);# \\1\\2\\n\\1' + newval + ';']
    finput = open(ifile)
    statinf = os.stat(ifile)
    tmpf = tempfile.NamedTemporaryFile(dir="/var/tmp")
    p = Popen(cmd, stdout=tmpf, stderr=PIPE, stdin=finput)
    p.wait()
    tmpf.flush()
    shutil.copyfile(tmpf.name, ifile)
    os.chown(ifile, statinf.st_uid, statinf.st_gid)
    tmpf.close()

# Configure Horizon dashboard WebGUI
def horizon():
    if get_os_release() == "5.12":
        # Need to disable webui from using port 443 for now because Horizon uses it
        check_call(["/usr/sbin/svccfg", "-s", "svc:/system/webui/server:default",
            "setprop", "conf/redirect_from_https=false"])

    if USE_SSL:
        print "configuring horizon for https"
        populate_horizon_cert_dirs()

        print "configuring horizon"
        check_call(["/usr/sbin/svccfg", "-s", "horizon:default", "setprop",
                    "config/use_tls", "=", "true"])
        check_call(["/usr/sbin/svccfg", "-s", "horizon:default", "setprop",
                    "config/ssl_cert_file", "=", HORIZON_CERT])
        check_call(["/usr/sbin/svccfg", "-s", "horizon:default", "setprop",
                    "config/ssl_ca_cert_file", "=", SOL_CACERTS_FILE])
        check_call(["/usr/sbin/svccfg", "-s", "horizon:default", "setprop",
                    "config/ssl_cert_key_file", "=", HORIZON_KEY])

        tfile = "/etc/openstack_dashboard/local_settings.py"
        cfg_file_change_param(tfile, "OPENSTACK_HOST",
                 '"' + KEYSTONE_NODE + '"')
        cfg_file_change_param(tfile, "OPENSTACK_KEYSTONE_URL",
            '"' + "https://%s:5000/v2.0" % KEYSTONE_NODE + '"')
        cfg_file_change_param(tfile, "OPENSTACK_SSL_CACERT",
            '"' + SOL_CACERTS_FILE + '"')
    else:
        print "configuring horizon for http"

        print "configuring horizon"
        check_call(["/usr/sbin/svccfg", "-s", "horizon:default", "setprop",
                    "config/use_tls", "=", "false"])

    check_call(["/usr/sbin/svccfg", "-s", "horizon:default", "setprop",
                "config/servername", "=", KEYSTONE_NODE])

    cmd = ["/usr/bin/svcs", "-H", "-o", "state", "horizon:default"]
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if out.strip() == "disabled":
        check_call(["/usr/sbin/svcadm", "refresh", "horizon:default"])
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "horizon:default"])
    else:
        check_call(["/usr/sbin/svcadm", "disable", "-s", "horizon:default"])
        check_call(["/usr/sbin/svcadm", "refresh", "horizon:default"])
        check_call(["/usr/sbin/svcadm", "enable", "-s", "horizon:default"])

def heat():
    print "configuring heat"

    service = "heat"
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/heat/heat.conf"))
    #config.set("DEFAULT", "verbose", "true")
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("DEFAULT", "region_name_for_services", REGION_NAME)
        config.set("database", "connection",
                   "mysql://heat:heat-pass@%s/heat?ssl_ca=%s" \
                        % (DB_NODE, SOL_CACERTS_FILE))
        #config.set("clients", "ca_file", ca)
        config.set("auth_password", "allowed_auth_uris", AUTH_URI)
        config.set("heat_api", "cert_file", servercert)
        config.set("heat_api", "key_file", serverkey)
        config.set("clients", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients", "cert_file", clientcert)
        #config.set("clients", "key_file", clientkey)
        config.set("clients", "insecure", "false")
        config.set("clients_cinder", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_cinder", "cert_file", clientcert)
        #config.set("clients_cinder", "key_file", clientkey)
        config.set("clients_cinder", "insecure", "false")
        config.set("clients_glance", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_glance", "cert_file", clientcert)
        #config.set("clients_glance", "key_file", clientkey)
        config.set("clients_glance", "insecure", "false")
        config.set("clients_heat", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_heat", "cert_file", clientcert)
        #config.set("clients_heat", "key_file", clientkey)
        config.set("clients_heat", "insecure", "false")
        config.set("clients_keystone", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_keystone", "cert_file", clientcert)
        #config.set("clients_keystone", "key_file", clientkey)
        config.set("clients_keystone", "insecure", "false")
        config.set("clients_neutron", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_neutron", "cert_file", clientcert)
        #config.set("clients_neutron", "key_file", clientkey)
        config.set("clients_neutron", "insecure", "false")
        config.set("clients_nova", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_nova", "cert_file", clientcert)
        #config.set("clients_nova", "key_file", clientkey)
        config.set("clients_nova", "insecure", "false")
        config.set("clients_swift", "ca_file", SOL_CACERTS_FILE)
        #config.set("clients_swift", "cert_file", clientcert)
        #config.set("clients_swift", "key_file", clientkey)
        config.set("clients_swift", "insecure", "false")
        #config.set("ec2authtoken", "allowed_auth_uris", AUTH_URI)
        #config.set("ec2authtoken", "auth_uri", AUTH_URI)
        #config.set("ec2authtoken", "ca_file", SOL_CACERTS_FILE)
        #config.set("ec2authtoken", "cert_file", clientcert)
        #config.set("ec2authtoken", "key_file", clientkey)
        #config.set("ec2authtoken", "insecure", "false")
        cfg_fill_in(config, service)
    else:
        config.set("database", "connection",
                 "mysql://heat:heat-pass@%s/heat" % DB_NODE)
        cfg_fill_in(config, service)

    if USE_CEILOMETER:
        config.set("DEFAULT", "notification_driver",
          "oslo.messaging.notifier.Notifier")

    with open("/etc/heat/heat.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/heat/api-paste.ini"))
    cfg_paste_fill_in(config, service)
    with open("/etc/heat/api-paste.ini", "wb") as fh:
        config.write(fh)

    print "enabling heat services"
    check_call(["/usr/sbin/svcadm", "refresh", "heat-api:default",
        "heat-api-cfn:default", "heat-api-cloudwatch:default"])
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "heat-api:default", "heat-db",
        "heat-engine", "heat-api-cfn:default", "heat-api-cloudwatch:default"])

    # OIB v
    time.sleep(4)

    print "testing heat"
    print "heat stack-list:"
    if USE_SSL:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "heat",
             "OS_CACERT": SOL_CACERTS_FILE,
             "OS_TENANT_NAME": SERVICE_PROJECT}
    else:
        env={"OS_AUTH_URL": SERVICE_ENDPOINT,
             "OS_PASSWORD": SERVICE_PASSWORD,
             "OS_USERNAME": "heat",
             "OS_TENANT_NAME": SERVICE_PROJECT}

    check_call(["/usr/bin/openstack", "stack", "list"], env=env)

@with_spinner
def pkg_install(pkg):
    swrite = lambda x: sys.stdout.write('\r' + x + '   ')

    todo = []
    if isinstance(pkg, str):
        pkg = [pkg]

    for p in pkg:
        cmd = ['/usr/bin/pkg', 'list', p]
        try:
            check_call(cmd, stdout=PIPE, stderr=PIPE)
        except CalledProcessError:
            todo.append(p)

    if not todo:
        return

    swrite('installing %s' % ", ".join(pkg))
    cmd = ['/usr/bin/pkg', 'install', '--accept']
    cmd.extend(pkg)

    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if p.returncode not in (0, 4):
        swrite('Error installing: %s' % pkg)
        swrite('---')
        swrite(out)
        swrite('---')
        swrite(err)


def swift_gen_hash():
    cmd = ["/usr/bin/od", "-t", "x8", "-N", "8", "-A", "n"]
    myinput = open('/dev/random')
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=myinput)
    out, err = p.communicate()
    myinput.close()

    out = out.strip()

    return out

# Expect swiftclient package
def swift_storage():
    print "creating ZFS datasets"

    if USE_SSL:
        populate_cert_dirs("swift")

    try:
        check_call(["/usr/sbin/zfs", "list", SWIFT_DATASET],
                   stdout=PIPE, stderr=PIPE)
    except:
        # doesn't exist; create it
        check_call(["/usr/sbin/zfs", "create", "-o", "mountpoint=none",
          SWIFT_DATASET])

    try:
        check_call(["/usr/sbin/zfs", "list", SWIFT_SRV_DATASET],
                   stdout=PIPE, stderr=PIPE)
    except:
        # doesn't exist; create it
        check_call(["/usr/sbin/zfs", "create", "-o", "mountpoint=/srv",
          SWIFT_SRV_DATASET])

    try:
        check_call(["/usr/sbin/zfs", "list", SWIFT_NODE_DATASET],
                   stdout=PIPE, stderr=PIPE)
    except:
        # doesn't exist; create it
        check_call(["/usr/sbin/zfs", "create",
          SWIFT_NODE_DATASET])

    try:
        check_call(["/usr/sbin/zfs", "list",
                    "%s/disk0" % SWIFT_NODE_DATASET],
                    stdout=PIPE, stderr=PIPE)
    except:
        # doesn't exist; create it
        check_call(["/usr/sbin/zfs", "create",
                    "%s/disk0" % SWIFT_NODE_DATASET])

    check_call(["/usr/bin/chown", "-R", "swift:swift", "/srv"])
    check_call(["/usr/bin/chown", "-R", "swift:swift", "/etc/swift"])

    # Enable everything except proxy
    print "Enabling Swift Storage Services..."
    check_call(["/usr/sbin/svcadm", "refresh",
      "swift-container-server:default",
      "swift-account-server:default",
      "swift-object-server:default"])

    check_call(["/usr/sbin/svcadm", "enable", "-rs",
      "swift-replicator-rsync", "swift-account-replicator",
      "swift-container-sync", "swift-container-server:default", "swift-account-auditor",
      "swift-container-updater", "swift-container-reconciler",
      "swift-container-replicator", "swift-container-auditor",
      "swift-account-reaper", "swift-account-server:default", "swift-object-expirer",
      "swift-object-auditor", "swift-object-server:default", "swift-object-replicator",
      "swift-object-updater", "swift-account-server:default"])

    # OIB v : reduce
    #time.sleep(5)

    print "testing swift"
    if USE_SSL:
        env = {
          "OS_AUTH_URL": SERVICE_ENDPOINT,
          "OS_CACERT": SOL_CACERTS_FILE,
          "OS_USERNAME": ADMIN_USER,
          "OS_PASSWORD": ADMIN_PASSWORD,
          "OS_TENANT_NAME": DEFAULT_PROJECT
        }
    else:
        env = {
          "OS_AUTH_URL": SERVICE_ENDPOINT,
          "OS_USERNAME": ADMIN_USER,
          "OS_PASSWORD": ADMIN_PASSWORD,
          "OS_TENANT_NAME": DEFAULT_PROJECT
        }


    # XXX It appears Swift has a bug here.  First container create fails, then
    # the subsequent container create (same container name used) succeeds. The
    # same behavior was experienced using the Eventlet server as well.  The container
    # is created even in the failing cases.  The same behavior is observed with both
    # OSC and swift client
    check_call(["/usr/bin/openstack", "container", "create", "container0"], env=env)
    # XXX Swift bug?
    time.sleep(5)
    check_call(["/usr/bin/openstack", "container", "list"], env=env)
    check_call(["/usr/bin/openstack", "object", "create", "container0", "/etc/motd"], env=env)
    check_call(["/usr/bin/openstack", "object", "show", "container0", "/etc/motd"], env=env)

    try:
        os.unlink("/tmp/swifttest")
    except:
        pass
    check_call(["/usr/bin/openstack", "object", "save", "--file", "/tmp/swifttest", "container0",
        "/etc/motd"], env=env)

    check_call(["/usr/bin/diff", "/tmp/swifttest", "/etc/motd"])
    try:
        os.unlink("/tmp/swifttest")
    except:
        pass

    check_call(["/usr/bin/openstack", "object", "delete", "container0", "/etc/motd"], env=env)


def swift_proxy():
    print "configuring swift"

    # Generate hash
    hash_suffix = swift_gen_hash()
    hash_prefix = swift_gen_hash()

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/swift.conf"))
    config.set("swift-hash", "swift_hash_path_suffix", hash_suffix)
    config.set("swift-hash", "swift_hash_path_prefix", hash_prefix)
    with open("/etc/swift/swift.conf", "wb") as fh:
        config.write(fh)

    service = "swift"
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/proxy-server.conf"))
    if not config.has_section("filter:authtoken"):
        config.add_section("filter:authtoken")
    cfg_paste_fill_in(config, service)
    config.set("DEFAULT", "bind_port", "8080")

    # Logging workaround 18692518
    # Use remote syslog
    config.set("DEFAULT", "log_name", "swift-proxy-server")
    config.set("DEFAULT", "log_facility", "LOG_LOCAL0")
    config.set("DEFAULT", "log_level", "WARNING")
    config.set("DEFAULT", "log_level", "DEBUG")
    config.set("DEFAULT", "log_udp_host", "localhost")
    config.set("DEFAULT", "log_udp_port", "514")

    # Swift requires external SSL termination in production
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")
        config.set("DEFAULT", "cert_file", servercert)
        config.set("DEFAULT", "key_file", serverkey)

    pipeline = "catch_errors healthcheck proxy-logging cache"

    # If Swift3 is installed use it for S3 interface
    # Need to install S3 egg, which only now can be done by pulling
    # Github at https://github.com/openstack/swift3 and running the
    # installation script.
    if ( os.path.exists("/usr/lib/python2.7/site-packages/swift3") or
       os.path.exists("/usr/lib/python2.7/vendor-packages/swift3") ):
        print "Configuring Swift S3"
        pipeline += " swift3 s3token"
        config.set("DEFAULT", "operator_roles", "admin, swiftoperator")
        if not config.has_section("filter:swift3"):
            config.add_section("filter:swift3")
        config.set("filter:swift3", "use", "egg:swift3#swift3")
        if not config.has_section("filter:s3token"):
            config.add_section("filter:s3token")
        config.set("filter:s3token", "paste.filter_factory",
            "keystonemiddleware.s3_token:filter_factory")
        config.set("filter:s3token", "auth_host", KEYSTONE_NODE)
        config.set("filter:s3token", "auth_port", "35357")
        config.set("filter:s3token", "signing_dir",
                        "/var/lib/swift/keystone-signing")
        if USE_SSL:
            config.set("filter:s3token", "auth_protocol", "https")
            # s3token doesn't allow cafile to pass through for keystone
            # authetication.
            # Use insecure as a workaround for self-signed certs
            config.set("filter:s3token", "insecure", "true")
            config.set("filter:s3token", "cafile",
                         SOL_CACERTS_FILE)
            # Workaround s3token lack of specifying cafile for self-seigned cert
            # it appears this only impacts authtoken if s3token is used
            config.set("filter:authtoken", "insecure", "true")
        else:
            config.set("filter:s3token", "auth_protocol", "http")

    pipeline += ( " authtoken keystoneauth bulk cache slo ratelimit " +
                "container-quotas account-quotas proxy-logging proxy-server" )

    config.set("pipeline:main", "pipeline", pipeline)
    config.set("app:proxy-server", "account_autocreate", "true")
    cfg_paste_fill_in(config, service)
    config.set("filter:authtoken", "delay_auth_decision", "true")
    config.set("filter:authtoken", "cache", "swift.cache")
    config.set("filter:authtoken", "include_service_catalog", "false")
    if not config.has_section("filter:keystoneauth"):
        config.add_section("filter:keystoneauth")
    config.set("filter:keystoneauth", "use", "egg:swift#keystoneauth")
    # Using a local memcache server for performance reasons
    config.set("filter:cache", "memcache_servers", "127.0.0.1:11211")
    with open("/etc/swift/proxy-server.conf", "wb") as fh:
        config.write(fh)

    # XXX research and test
    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/dispersion.conf"))
    config.set("dispersion", "auth_url", PUBLIC_ENDPOINT)
    config.set("dispersion", "auth_user", "%s:%s" % (SERVICE_PROJECT, "swift"))
    config.set("dispersion", "auth_key", SERVICE_PASSWORD)
    config.set("dispersion", "auth_version", "2.0")
    if USE_SSL:
        config.set("dispersion", "keystone_api_insecure", "no")
    with open("/etc/swift/dispersion.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/container-server.conf"))
    # Logging workaround 18692518
    config.set("DEFAULT", "log_name", "swift-container-server")
    config.set("DEFAULT", "log_facility", "LOG_LOCAL0")
    config.set("DEFAULT", "log_level", "WARNING")
    #config.set("DEFAULT", "log_level", "DEBUG")
    config.set("DEFAULT", "log_udp_host", "localhost")
    config.set("DEFAULT", "log_udp_port", "514")
    with open("/etc/swift/container-server.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/account-server.conf"))
    # Logging workaround 18692518
    # Use remote syslog
    config.set("DEFAULT", "log_name", "swift-account-server")
    config.set("DEFAULT", "log_facility", "LOG_LOCAL0")
    config.set("DEFAULT", "log_level", "WARNING")
    #config.set("DEFAULT", "log_level", "DEBUG")
    config.set("DEFAULT", "log_udp_host", "localhost")
    config.set("DEFAULT", "log_udp_port", "514")
    with open("/etc/swift/account-server.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/container-reconciler.conf"))
    # Logging workaround 18692518
    # Use remote syslog
    config.set("DEFAULT", "log_name", "swift-container-reconciler")
    config.set("DEFAULT", "log_facility", "LOG_LOCAL0")
    config.set("DEFAULT", "log_level", "WARNING")
    #config.set("DEFAULT", "log_level", "DEBUG")
    config.set("DEFAULT", "log_udp_host", "localhost")
    config.set("DEFAULT", "log_udp_port", "514")
    with open("/etc/swift/container-reconciler.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/object-expirer.conf"))
    # Logging workaround 18692518
    # Use remote syslog
    config.set("DEFAULT", "log_name", "swift-object-expirer")
    config.set("DEFAULT", "log_facility", "LOG_LOCAL0")
    config.set("DEFAULT", "log_level", "WARNING")
    #config.set("DEFAULT", "log_level", "DEBUG")
    config.set("DEFAULT", "log_udp_host", "localhost")
    config.set("DEFAULT", "log_udp_port", "514")
    with open("/etc/swift/object-expirer.conf", "wb") as fh:
        config.write(fh)

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/swift/object-server.conf"))
    # Logging workaround 18692518
    # Use remote syslog
    config.set("DEFAULT", "log_name", "swift-object-server")
    config.set("DEFAULT", "log_facility", "LOG_LOCAL0")
    config.set("DEFAULT", "log_level", "WARNING")
    #config.set("DEFAULT", "log_level", "DEBUG")
    config.set("DEFAULT", "log_udp_host", "localhost")
    config.set("DEFAULT", "log_udp_port", "514")
    with open("/etc/swift/object-server.conf", "wb") as fh:
        config.write(fh)

    print "building rings"

    def rb(type, action, *args):
        check_call(["/usr/bin/swift-ring-builder",
          "/etc/swift/%s.builder" % type, action] + list(args))

    port = {"object": 6000, "container": 6001, "account": 6002}
    ipv4addr = MY_IP
    if ipv4addr != "127.0.0.1":
        print "swift cluster using %s" % ipv4addr
    else:
        ipv4addr = "127.0.0.1"
        print "swift cluster using %s on loopback" % ipv4addr
        print "You may want to change this with:"
        print "    # swift-ring-builder /etc/swift/<type>.builder set_info 127.0.0.1 <ip>"
        print "    # swift-ring-builder /etc/swift/<type>.builder write_ring"
        print "where <type> is set to 'object', 'container', and 'account' and"
        print "<ip> is set to the IP address you want the cluster to use."
    for t in port.keys():
        #rb(t, "create", "10", "3", "1") # XXX
        rb(t, "create", "10", "1", "1")
        rb(t, "add", "r1z1-%s:%s/disk0" % (ipv4addr, port[t]), "100")
        rb(t, "rebalance")

    # Logging workaround 18692518
    # Configure syslog for Swift
    with open("/etc/syslog.conf", "a") as f:
        f.write("\n")
        f.write("local0.err\t\t\t/var/log/swift/proxy.error\n")
        f.write("local0.debug\t\t\t/var/log/swift/proxy.log\n")
        f.write("local0.info\t\t\t/var/log/swift/proxy.log\n")
        f.write("local0.notice\t\t\t/var/log/swift/proxy.log\n")
        f.write("local0.warning\t\t\t/var/log/swift/proxy.log\n")
    f.close()
    # Create inital log files
    if not os.path.exists("/var/log/swift"):
        os.makedirs("/var/log/swift", 0755)
    os.chown("/var/log/swift", pwd.getpwnam("swift").pw_uid,
        grp.getgrnam("swift").gr_gid)
    open("/var/log/swift/proxy.error", 'a').close()
    open("/var/log/swift/proxy.log", 'a').close()

    # Restart syslog with remote logging
    check_call(["/usr/sbin/svccfg", "-s", "svc:/system/system-log:default",
                 "setprop", "config/log_from_remote=true"])
    check_call(["/usr/sbin/svcadm", "refresh",
                 "svc:/system/system-log:default"])
    check_call(["/usr/sbin/svcadm", "restart",
                 "svc:/system/system-log:default"])
    # end workaround 18692518

    check_call(["/usr/sbin/svcadm", "enable", "-rs", "memcached"])

    print "enabling swift services"
    check_call(["/usr/sbin/svcadm", "refresh", "swift-proxy-server:default"])
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "swift-proxy-server:default"])
    # OIB v
    time.sleep(4)

    if USE_SSL:
        env = {
          "OS_AUTH_URL": SERVICE_ENDPOINT,
          "OS_USERNAME": ADMIN_USER,
          "OS_PASSWORD": ADMIN_PASSWORD,
          "OS_TENANT_NAME": DEFAULT_PROJECT,
          "OS_CACERT": SOL_CACERTS_FILE,
        }
    else:
        env = {
          "OS_AUTH_URL": SERVICE_ENDPOINT,
          "OS_USERNAME": ADMIN_USER,
          "OS_PASSWORD": ADMIN_PASSWORD,
          "OS_TENANT_NAME": DEFAULT_PROJECT,
        }

    # Create a Swift operator role and add to the admin user
    check_call(["/usr/bin/openstack", "role", "create", "swiftoperator"], env=env)
    service_uuid = get_tenant_uuid(SERVICE_PROJECT, env)
    check_call(["/usr/bin/openstack", "role", "add", "--user", ADMIN_USER,
        "--project", service_uuid, "swiftoperator"], env=env)

# Prepare SSH keys for Ironic
def ironic_prep():
    """Prepare ironic user for SSH authentication"""
    ironic = pwd.getpwnam("ironic")

    print "creating ssh keys"
    ironic_pubkey = create_pubkey(ironic)

    print "setting .ssh/config"
    ssh_config = "Host *\n\tStrictHostKeyChecking no\n"
    ssh_config_path = os.path.join(ironic.pw_dir, ".ssh", "config")
    with open(ssh_config_path, "w") as fh:
        fh.write(ssh_config)
    os.chmod(ssh_config_path, 0600)

    print "populating authorized_keys"
    path = os.path.join(ironic.pw_dir, ".ssh", "authorized_keys")
    with open(path, "w") as fh:
        fh.write(ironic_pubkey)

    owner = "%s:%s" % (ironic.pw_name, grp.getgrgid(ironic.pw_gid).gr_name)
    check_call(["/usr/bin/chown", "-R", owner,
               os.path.join(ironic.pw_dir, ".ssh", "authorized_keys")])

# Configure the Ironic bare-metal service
def ironic():
    service = "ironic"
    print "configuring ironic"

    # If the AI server is on the controller, we prepare it
    if AI_ON_CONTROLLER:
        ironic_prep()

    config = iniparse.SafeConfigParser()
    config.readfp(open("/etc/ironic/ironic.conf"))
    if USE_SSL:
        populate_cert_dirs(service)
        servercert = get_ssl_path(service, "servercert-fchain")
        serverkey = get_ssl_path(service, "serverkey")
        #clientcert = get_ssl_path(service, "clientcert")
        #clientkey = get_ssl_path(service, "clientkey")

        config.set("database", "connection",
                   "mysql://ironic:ironic-pass@%s/ironic?ssl_ca=%s" \
                        % (DB_NODE, SOL_CACERTS_FILE))
        config.set("neutron", "url", "https://%s:9696" % NEUTRON_NODE)
        config.set("glance", "glance_protocol", "https")
        config.set("glance", "glance_api_insecure", "false")
        config.set("glance", "glance_api_servers",
                         "https://%s:9292" % GLANCE_NODE)
        config.set("glance", "glance_protocol", "https")
    else:
        config.set("neutron", "url", "http://%s:9696" % NEUTRON_NODE)
        config.set("database", "connection",
                         "mysql://ironic:ironic-pass@%s/ironic" % DB_NODE)
        config.set("glance", "glance_api_servers",
                         "http://%s:9292" % GLANCE_NODE)
        config.set("glance", "glance_protocol", "http")

    # Kilo Ironic doesn't appear to allow a TLS endpoint
    config.set("conductor", "api_url", "http://%s:6385/" % IRONIC_NODE)

    cfg_fill_in(config, service)

    config.set("DEFAULT", "auth_strategy", "keystone")
    config.set("DEFAULT", "enabled_drivers", "solaris")
    config.set("ai", "server", AI_NODE)
    config.set("ai", "username", "ironic")
    config.set("ai", "port", "22")
    config.set("ai", "timeout", "10")
    config.set("ai", "deploy_interval", "30")
    config.set("ai", "ssh_key_file", "/var/lib/ironic/.ssh/id_rsa")
    config.set("conductor", "heartbeat_interval", "60")
    config.set("conductor", "heartbeat_timeout", "60")
    config.set("conductor", "check_provision_state_interval", "120")
    config.set("conductor", "sync_power_state_interval", "300")
    config.set("glance", "glance_host", GLANCE_NODE)
    config.set("solaris_ipmi", "imagecache_dirname", "/var/lib/ironic/images")
    config.set("solaris_ipmi", "imagecache_lock_timeout", "60")
    config.set("api", "host_ip", socket.gethostbyname(IRONIC_NODE))
    config.set("DEFAULT", "my_ip", socket.gethostbyname(IRONIC_NODE))
    with open("/etc/ironic/ironic.conf", "wb") as fh:
        config.write(fh)

    print "enabling ironic services"
    check_call(["/usr/sbin/svcadm", "refresh", "ironic-api:default"])
    check_call(["/usr/sbin/svcadm", "enable", "-rs", "ironic-db",
        "ironic-api:default", "ironic-conductor"])

    # OIB v
    time.sleep(3)

    print "testing ironic"
    print "ironic driver-list:"
    if USE_SSL:
        check_call(["/usr/bin/ironic", "driver-list"],
           env={"OS_USERNAME": "ironic",
                "OS_CACERT": SOL_CACERTS_FILE,
                "OS_AUTH_URL": SERVICE_ENDPOINT,
                "OS_PASSWORD": SERVICE_PASSWORD,
                "OS_TENANT_NAME": SERVICE_PROJECT})
    else:
        check_call(["/usr/bin/ironic", "driver-list"],
           env={"OS_USERNAME": "ironic",
                "OS_AUTH_URL": SERVICE_ENDPOINT,
                "OS_PASSWORD": SERVICE_PASSWORD,
                "OS_TENANT_NAME": SERVICE_PROJECT})

    print "NOTE: Ironic expecting AI Server on localhost"

# Invoked on a separate AI server to prep for Ironic
def ironic_aiserver_config():
    check_call(["/usr/sbin/useradd", "-d", "/var/lib/ironic", "-m", "-g",
                "88", "-u", "88", "-P", "\"Install Service Management\"",
                "ironic"])

    # Create a password for ironic
    check_call(["/usr/bin/passwd", "ironic"])

    ironic_prep()

    print "Copy keys to the Ironic server as follows:"
    print ( "cat ironic@%s:~/.ssh/id_rsa.pub | ssh root@%s 'umask 0077;" +
        " mkdir -p /var/lib/ironic/.ssh; cat >> " +
        "/var/lib/ironic/.ssh/authorized_keys'" % (MY_NAME, IRONIC_NODE))
    print "ssh root@%s 'chown -R ironic:ironic /var/lib/ironic/.ssh" \
                % IRONIC_NODE
    print "scp ironic@%s:~/.ssh/id_rsa root@%s:~/.ssh/id_rsa" \
                % (MY_NAME, IRONIC_NODE)
    print "scp ironic@%s:~/.ssh/id_rsa root@%s:/var/lib/ironic/.ssh" \
                % (MY_NAME, IRONIC_NODE)
    print "scp ironic@%s:~/.ssh/id_rsa.pub root@%s:~/.ssh/id_rsa.pub" \
                % (MY_NAME, IRONIC_NODE)
    print "scp ironic@%s:~/.ssh/id_rsa.pub root@%s:/var/lib/ironic/.ssh" \
                % (MY_NAME, IRONIC_NODE)

    keyin = raw_input("Press <Enter> when copied")

def ceilometer(glance=True, neutron=True, nova=True, swift=True):
    print "configuring ceilometer"

    config = iniparse.ConfigParser()
    config.readfp(open("/etc/ceilometer/ceilometer.conf"))

    config.set("database", "connection",
               "mysql://ceilometer:ceilometer@localhost/ceilometer")

    # The service_types config section maps service names as known to ceilometer
    # to service types as known to keystone.  If services of those types are
    # registered in keystone, but aren't up and running, then
    # ceilometer-agent-central will complain periodically with tracebacks that
    # they're not reachable.  If no service of the given service type is known,
    # then it complains quietly.  Because the keystone demo script registers
    # these services, but we don't necessarily set up each service, then quiet
    # ceilometer for the ones where we don't.
    if not glance:
        config.set("service_types", "glance", "image-disabled")
    if not neutron:
        config.set("service_types", "neutron", "network-disabled")
    if not nova:
        config.set("service_types", "nova", "compute-disabled")
    if not swift:
        config.set("service_types", "swift", "object-store-disabled")
    # This is the Ceph storage service, which uses the object-store service type
    # just like swift.  It'll always complain on one of our setups, so always
    # shut it up.
    config.set("service_types", "radosgw", "object-store-disabled")

    config.set("DEFAULT", "hypervisor_inspector", "solariszones")

    # XXX So which is it?  service_credentials or keystone_authtoken?
    config.set("service_credentials", "os_tenant_name", "service")
    config.set("service_credentials", "os_username", "ceilometer")
    config.set("service_credentials", "os_password", "ceilometer")
    config.set("keystone_authtoken", "admin_tenant_name", "service")
    config.set("keystone_authtoken", "admin_user", "ceilometer")
    config.set("keystone_authtoken", "admin_password", "ceilometer")

    config.set("keystone_authtoken", "auth_uri", "http://127.0.0.1:5000/v2.0/")
    config.set("keystone_authtoken", "identity_uri", "http://127.0.0.1:35357")

    with open("/etc/ceilometer/ceilometer.conf", "wb") as fh:
        config.write(fh)

# Configure RabbitMQ messaging service
def rabbitmq():
    # install rabbit if needed and start it
    pkg_install('rabbitmq')

    if RABBITMQ_USE_SSL:
        populate_cert_dirs("rabbitmq")
        # Updated conf file to use certs
        shutil.copyfile("rabbitmq.config.ssl", "/etc/rabbitmq/rabbitmq.config")

    cmd = ["/usr/bin/svcs", "-H", "-o", "state", "rabbitmq"]
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if out.strip() == "disabled":
        check_call(["/usr/sbin/svcadm", "enable", "-rs", "rabbitmq"])

    # OIB v
    time.sleep(3)

    # Delete the guest user because we created a new one
    check_call(["/usr/bin/rabbitmqctl", "delete_user", "guest"])
    check_call(["/usr/bin/rabbitmqctl", "add_user", RABBITMQ_USER,
                 RABBITMQ_PASS])
    check_call(["/usr/bin/rabbitmqctl", "set_user_tags",
         RABBITMQ_USER, "administrator"])
    check_call(["/usr/bin/rabbitmqctl", "set_permissions",
         "-p", "/", RABBITMQ_USER, ".*", ".*", ".*" ])

# Generic paths for the keys
def get_ssl_path(service, ssltype):
    certs_dir = "/etc/%s/ssl" % service
    private_dir = certs_dir + "/private"
    public_dir = certs_dir + "/public"

    if ssltype == "servercert":
        return "%s/%s" % (public_dir, "server-cert.pem")
    if ssltype == "servercert-fchain":
        return "%s/%s" % (public_dir, "server-cert-fchain.pem")
    if ssltype == "serverkey":
        return "%s/%s" % (private_dir, "server-key.pem")
    if ssltype == "clientcert":
        return "%s/%s" % (public_dir, "client-cert.pem")
    if ssltype == "clientkey":
        return "%s/%s" % (private_dir, "client-key.pem")

DASHBOARD_DIR = "/etc/openstack_dashboard"
HORIZON_CERT = "%s/horizon.crt" % DASHBOARD_DIR
HORIZON_KEY = "%s/horizon.key" % DASHBOARD_DIR
# Horizon has a special path
def populate_horizon_cert_dirs():
    shutil.copyfile(SSL_HZN_SERVER_CERT_FILE, HORIZON_CERT)
    shutil.copyfile(SSL_HZN_SERVER_KEY_FILE, HORIZON_KEY)

    call(["/usr/bin/chown", "-R", "webservd:webservd", DASHBOARD_DIR])
    os.chmod(HORIZON_CERT, 0644)
    os.chmod(HORIZON_KEY, 0640)
    os.chmod(DASHBOARD_DIR, 0755)

# populates certificates in each service config directory
def populate_cert_dirs(service):
    servpath = "/etc/%s" % service
    if not os.path.exists(servpath):
        raise RuntimeError()

    certs_dir = "/etc/%s/ssl" % service

    if os.path.exists(certs_dir):
        shutil.rmtree(certs_dir)

    private_dir = certs_dir + "/private"
    public_dir = certs_dir + "/public"
    if not os.path.exists(public_dir):
        os.makedirs(public_dir, 0750)
    if not os.path.exists(private_dir):
        os.makedirs(private_dir, 0750)

    fname = "%s/%s" % (public_dir, "server-cert.pem")
    shutil.copyfile(SSL_SERVER_CERT_FILE, fname)
    os.chmod(fname, 0640)
    fname = "%s/%s" % (public_dir, "server-cert-fchain.pem")
    shutil.copyfile(SSL_SERVER_CERT_FCHAIN_FILE, fname)
    os.chmod(fname, 0640)
    fname = "%s/%s" % (private_dir, "server-key.pem")
    shutil.copyfile(SSL_SERVER_KEY_FILE, fname)
    os.chmod(fname, 0640)

    call(["/usr/bin/chown", "-R", service, certs_dir])

ENVVARS_SUBDIR = "./env"

# List of users, pws and projects that sample_data.sh created
UNPW_LIST = [(ADMIN_USER, ADMIN_PASSWORD, DEFAULT_PROJECT),
          ("nova", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("glance", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("ec2", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("swift", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("neutron", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("cinder", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("heat", SERVICE_PASSWORD, SERVICE_PROJECT),
          ("ironic", SERVICE_PASSWORD, SERVICE_PROJECT)]

# Creates environment files for operator to source so
# Openstack CLI commands can be used.
def create_env_files():
    if not os.path.exists(ENVVARS_SUBDIR):
        os.mkdir(ENVVARS_SUBDIR)
    os.chown(ENVVARS_SUBDIR, pwd.getpwnam("root").pw_uid,
             grp.getgrnam("root").gr_gid)

    for user,pw,tenant,addr,floatingips,allocfips in TENANT_NET_LIST:
        fname = ENVVARS_SUBDIR + "/" + user + ".env"
        f = open(fname, 'w')
        f.write("u=$(/usr/bin/env | /usr/bin/grep \"OS_.*\" | cut -d= -f1)\n")
        f.write('if [ ! -z "$u" ]; then\n')
        f.write("   unset $u\n")
        f.write("fi\n")
        f.write("export OS_IDENTITY_API_VERSION=2.0\n")
        f.write("export OS_AUTH_URL=%s\n" % SERVICE_ENDPOINT)
        f.write("export OS_NO_CACHE=1\n")
        f.write("export OS_USERNAME=%s\n" % user)
        f.write("export OS_PASSWORD=%s\n" % pw)
        f.write("export OS_TENANT_NAME=%s\n" % tenant)
        f.write("export OS_NO_CACHE=1\n")
        if USE_SSL:
            f.write("export OS_CACERT=%s\n" % SOL_CACERTS_FILE)
        f.close()
        os.chmod(fname, 0600)

    for user,pw,tenant in UNPW_LIST:
        fname = ENVVARS_SUBDIR + "/" + user + ".env"
        f = open(fname, 'w')
        f.write("u=$(/usr/bin/env | /usr/bin/grep \"OS_.*\" | cut -d= -f1)\n")
        f.write('if [ ! -z "$u" ]; then\n')
        f.write("   unset $u\n")
        f.write("fi\n")
        f.write("export OS_IDENTITY_API_VERSION=2.0\n")
        f.write("export OS_AUTH_URL=%s\n" % SERVICE_ENDPOINT)
        f.write("export OS_NO_CACHE=1\n")
        f.write("export OS_USERNAME=%s\n" % user)
        f.write("export OS_PASSWORD=%s\n" % pw)
        f.write("export OS_TENANT_NAME=%s\n" % tenant)
        f.write("export OS_NO_CACHE=1\n")
        if USE_SSL:
            f.write("export OS_CACERT=%s\n" % SOL_CACERTS_FILE)
        f.close()
        os.chmod(fname, 0600)

def tls_update_paths():
    global SSL_CACERT_FILE
    global SSL_CACHAINCERT_FILE
    global SSL_SERVER_CERT_FILE
    global SSL_SERVER_CERT_FCHAIN_FILE
    global SSL_SERVER_KEY_FILE
    global SSL_HZN_SERVER_CERT_FILE
    global SSL_HZN_SERVER_CERT_FCHAIN_FILE
    global SSL_HZN_SERVER_KEY_FILE

    # Paths to certs and keys for TLS/SSL
    # These paths are where os_keygen.py places generated keys
    SSL_KEYS_PATH = "keys"
    SSL_KEYS_INT_PATH = SSL_KEYS_PATH + "/intermediate"
    SSL_KEYS_CERTS_PATH = SSL_KEYS_INT_PATH + "/certs"
    SSL_KEYS_PRIV_PATH = SSL_KEYS_INT_PATH + "/private"

    SSL_CACERT_FILE = SSL_KEYS_CERTS_PATH + "/intermediate.cert.pem"
    SSL_CACHAINCERT_FILE = SSL_KEYS_CERTS_PATH + "/ca-chain.cert.pem"
    SSL_SERVER_CERT_FILE = SSL_KEYS_CERTS_PATH +"/%s-server.cert.pem" \
            % MY_NAME
    SSL_SERVER_CERT_FCHAIN_FILE = SSL_KEYS_CERTS_PATH + \
        "/%s-server-fchain.cert.pem" % MY_NAME
    SSL_SERVER_KEY_FILE = SSL_KEYS_PRIV_PATH + "/%s-server.key.pem" \
            % MY_NAME
    SSL_HZN_SERVER_CERT_FILE = SSL_KEYS_CERTS_PATH + "/%s-server.cert.pem" \
            % HORIZON_HOSTNAME
    SSL_HZN_SERVER_CERT_FCHAIN_FILE = SSL_KEYS_CERTS_PATH + \
        "/%s-server-fchain.cert.pem" % HORIZON_HOSTNAME
    SSL_HZN_SERVER_KEY_FILE = SSL_KEYS_PRIV_PATH + "/%s-server.key.pem" \
            % HORIZON_HOSTNAME

    SSL_CLIENT_CERT_FILE = SSL_KEYS_CERTS_PATH + "/osclient-client.cert.pem"
    SSL_CLIENT_KEY_FILE = SSL_KEYS_PRIV_PATH + "/osclient-client.key.pem"

def get_unique_nodel():
    # Create a list of hosts to generate certs/keys for
    uniquenl = []
    for n in nodelist:
        if n not in uniquenl:
            uniquenl.append(n)
    return uniquenl

# Generate Root CA, Intermediate CA and self-seigned certs/keys
# for testing TLS.
import os_keygen
def tls_gen_keys():
    os_keygen.init_keytree()
    os_keygen.create_root_ca_pair()
    os_keygen.create_root_ca_intermediate_pair()
    os_keygen.create_cert_chain_file()

    # Generate server cert/key for all unique nodes being
    # configured.
    uniquenl = get_unique_nodel()
    for n in uniquenl:
        basen = n.split('.')[0]
        if n != basen:
            alt_names = "DNS.1:%s,DNS.2:%s" % (n, basen)
        else:
            alt_names = "DNS.1:%s" % n
        os_keygen.sign_cert(n, "server", alt_names)

    if CONTROLLER_NODE != COMPUTE_NODE:
        n = COMPUTE_NODE
        basen = n.split('.')[0]
        if n != basen:
            alt_names = "DNS.1:%s,DNS.2:%s" % (n, basen)
        else:
            alt_names = "DNS.1:%s" % n
        os_keygen.sign_cert(n, "server", alt_names)

SOL_CERT_PATH = "/etc/certs/CA"
SOL_CERT_TEST_CA = SOL_CERT_PATH + "/openstack-test-cachain.pem"
# Add CA to the Solaris Custom Certificate Authority
def tls_add_cacert():
    shutil.copyfile(SSL_CACHAINCERT_FILE, SOL_CERT_TEST_CA)
    os.chmod(SOL_CERT_TEST_CA, 0644)
    check_call(["/usr/bin/chgrp", "sys", SOL_CERT_TEST_CA])
    print "Refreshing ca-certificates service..."
    check_call(["/usr/sbin/svcadm", "refresh", "-s",
        "system/ca-certificates:default"])
    check_call(["/usr/sbin/svcadm", "restart", "-s",
        "system/ca-certificates:default"])

def main(args):
    global MY_NAME
    global MY_IP

    hostname = os.environ.get('OS_HOSTNAME')
    if hostname:
        MY_NAME = hostname
        MY_IP = socket.gethostbyname(MY_NAME)

    service_list = ["memcached", "rabbitmq", "mysql", "keystone", "glance",
                    "cinder", "neutron", "horizon", "swift-proxy", "swift-storage",
                    "heat", "ironic", "nova-controller", "nova-compute",
                    "nova-single-node", "neutron-networking",
                    "ironic-aiserver-config", "glance-add-images", "gen-keys", "env"]

    if not args or args[0] == "-h" or args[0] == "help":
        print "USAGE:"
        print "  <controller|compute|singlenode|slist services...>>"
        print "  where services is list of following services"
        print "  to configure:"
        print ""
        print service_list
        print ""
        print "Environment variables:"
        print " OS_HOSTNAME=<hostname facing control network>"
        print ""
        sys.exit(1)

    action = args.pop(0)

    cmd = ["/usr/sbin/svcadm", "restart", "rad:local"]
    check_call(cmd)

    if action == "controller":
        SINGLE_NODE = False
        MY_NAME = CONTROLLER_NODE
        MY_IP = socket.gethostbyname(CONTROLLER_NODE)

        args = ["memcached", "rabbitmq", "mysql", "keystone", "glance", "nova-controller",
                "cinder", "neutron", "neutron-networking", "horizon", "swift-proxy", "swift-storage", "heat",
                "ironic", "glance-add-images"]

        # Generate keys when setting up the controller, they can be copied
        # to the other nodes after
        if SSL_GEN_CACERTS:
            # Generate keys
            tls_gen_keys()
            tls_update_paths()
        if USE_SSL:
            tls_add_cacert()

        create_env_files()

    elif action == "compute":
        SINGLE_NODE = False
        MY_NAME = COMPUTE_NODE
        MY_IP = socket.gethostbyname(COMPUTE_NODE)

        args = ["memcached", "nova-compute", "swift-storage", "bundle-create"]
        if SSL_GEN_CACERTS:
            tls_update_paths()
        if USE_SSL:
            tls_add_cacert()

        create_env_files()

    elif action == "singlenode":
        args = ["memcached", "rabbitmq", "mysql", "keystone", "glance", "nova-single-node",
                "cinder", "neutron", "neutron-networking", "horizon", "swift-proxy",
                "swift-storage", "heat", "ironic", "glance-add-images"]
        SINGLE_NODE = True
        if SSL_GEN_CACERTS:
            # Generate keys
            tls_gen_keys()
            tls_update_paths()
        if USE_SSL:
            tls_add_cacert()

        create_env_files()

    elif action == "slist":
        if SSL_GEN_CACERTS:
            tls_update_paths()

        invalid = False
        for a in args:
            if a not in service_list:
                print "%s: is not a valid service" % a
                invalid = True
        if invalid:
            sys.exit(1)
    else:
        print "$ %s help" % args[0]
        sys.exit(1)


    # Make sure Openstack is installed
    pkg_install(['cloud/openstack'])

    if "gen-keys" in args:
        tls_gen_keys()
        tls_add_cacert()

    if "env" in args:
        create_env_files()

    if "memcached" in args:
        check_call(["/usr/sbin/svcadm", "enable",
            "svc:/application/database/memcached:default"])

    if "rabbitmq" in args:
        rabbitmq()

    if "mysql" in args:
        mysql()

    if "keystone" in args:
        keystone()

    if "glance" in args:
        glance()

    if "cinder" in args:
        cinder()

    if "nova-controller" in args:
        nova_controller()

    if "nova-compute" in args:
        nova_compute()

    if "nova-single-node" in args:
        nova_single_node()

    if "horizon" in args:
        horizon()

    if "neutron" in args:
        neutron()

    if "neutron-networking" in args:
        neutron_networking()

    if "heat" in args:
        heat()

    if "ironic" in args:
        ironic()

    if "swift-proxy" in args:
        swift_proxy()

    if "swift-storage" in args:
        swift_storage()

    if "ironic-aiserver-config" in args:
        ironic_aiserver_config()

    if "glance-add-images" in args:
        glance_add_images()

if __name__ == "__main__":
    main(sys.argv[1:])
