#!/bin/bash

# Work to Kerberos in container
PASSWORD="Password01"
OLD_HOSTNAME=$(cat /etc/hostname)
NEW_HOSTNAME=ubuntu-dc
IP_ADDRESS=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
DOMAIN_NAME=example.com

echo "Changing hostname to $NEW_HOSTNAME"
echo "$NEW_HOSTNAME" > /etc/hostname
cat > /etc/hosts << EOL
127.0.0.1 localhost
127.0.0.1 $NEW_HOSTNAME
$IP_ADDRESS $NEW_HOSTNAME.$DOMAIN_NAME

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOL

hostnamectl set-hostname $NEW_HOSTNAME

echo "Setting up Kerberos configuration file at /etc/krb5.conf"
cat > /etc/krb5.conf << EOL
[libdefaults]
    default_realm = ${DOMAIN_NAME^^}

[realms]
    EXAMPLE.COM = {
        kdc = $NEW_HOSTNAME.$DOMAIN_NAME
        admin_server = $NEW_HOSTNAME.$DOMAIN_NAME
    }

[domain_realm]
    .$DOMAIN_NAME = ${DOMAIN_NAME^^}

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    default = FILE:/var/log/krb5lib.log
EOL

echo -e "*/*@${DOMAIN_NAME^^}\t*" > /var/kerberos/kadm5.acl

echo "Installing Kerberos libraries"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y krb5-{user,kdc,admin-server,multidev} libkrb5-dev

echo "Creating KDC database"
rm -rf /var/lib/krb5kdc/*
printf "$PASSWORD\n$PASSWORD" | krb5_newrealm

echo "Creating admin principal"
kadmin.local -q "addprinc -pw $PASSWORD administrator"

echo "Restarting Kerberos service"
service krb5-kdc restart

echo "Install Apache"
apt-get install -y apache2

echo "Add ServerName to Apache config"
grep -q -F "ServerName $NEW_HOSTNAME.$DOMAIN_NAME" /etc/apache2/apache2.conf || echo "ServerName $NEW_HOSTNAME.$DOMAIN_NAME" >> /etc/apache2/apache2.conf

echo "Deleting default virtual host file"
if [ -f /etc/apache2/sites-available/000-default.conf ]; then
    rm /etc/apache2/sites-available/000-default.conf
fi

if [ -f /etc/apache2/sites-enabled/000-default.conf ]; then
    rm /etc/apache2/sites-enabled/000-default.conf
fi

echo "Create website directory structure and pages"
mkdir -p /var/www/example.com/public_html
chmod -R 755 /var/www
echo "<html><head><title>Title</title></head><body>body mesage</body></html>" > /var/www/example.com/public_html/index.html

echo "Create virtual host files"
cat > /etc/apache2/sites-available/example.com.conf << EOL
<VirtualHost *:80>
    ServerName $NEW_HOSTNAME.$DOMAIN_NAME
    ServerAlias $NEW_HOSTNAME.$DOMAIN_NAME
    DocumentRoot /var/www/example.com/public_html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Directory "/var/www/example.com/public_html">
        AuthType GSSAPI
        AuthName "GSSAPI Single Sign On Login"
        Require user administrator@EXAMPLE.COM
        GssapiCredStore keytab:/etc/httpd.keytab  
    </Directory>
</VirtualHost>
EOL

echo "Enabling virtual host site"
a2ensite example.com.conf
systemctl reload apache2

echo "Installing mod-auth-gssapi"
apt-get install -y libapache2-mod-auth-gssapi

echo "Adding principal for Kerberos auth and creating keytab"
kadmin.local -q "addprinc -randkey HTTP/$NEW_HOSTNAME.$DOMAIN_NAME"
kadmin.local -q "ktadd -k /etc/httpd.keytab HTTP/$NEW_HOSTNAME.$DOMAIN_NAME"
chmod 777 /etc/httpd.keytab

echo "Getting ticket for Kerberos user"
echo -n "$PASSWORD" | kinit "administrator@EXAMPLE.COM"

echo "Try out the curl connection"
CURL_OUTPUT=$(curl --negotiate -u : "http://$NEW_HOSTNAME.$DOMAIN_NAME")

if [ "$CURL_OUTPUT" != "<html><head><title>Title</title></head><body>body mesage</body></html>" ]; then
    echo -e "ERROR: Did not get success message:\nActual Output:\n$CURL_OUTPUT"
fi
