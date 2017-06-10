#!/bin/bash

# Work to Kerberos in container
IP_ADDRESS=$(hostname -I)
HOSTNAME=$(cat /etc/hostname)
DOMAIN_NAME=example.com
PASSWORD=Password01

echo "Configuring hostname for $HOSTNAME"
cp /etc/hosts ~/hosts.new
sed -i "/.*$HOSTNAME/c\\$IP_ADDRESS\t$HOSTNAME.$DOMAIN_NAME" ~/hosts.new
cp -f ~/hosts.new /etc/hosts

echo "Setting up Kerberos configuration file at /etc/krb5.conf"
cat > /etc/krb5.conf << EOL
[libdefaults]
    default_realm = ${DOMAIN_NAME^^}
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    ${DOMAIN_NAME^^} = {
        kdc = $HOSTNAME.$DOMAIN_NAME
        admin_server = $HOSTNAME.$DOMAIN_NAME
    }

[domain_realm]
    .$DOMAIN_NAME = ${DOMAIN_NAME^^}

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    default = FILE:/var/log/krb5lib.log
EOL

mkdir /etc/krb5kdc
echo -e "*/*@${DOMAIN_NAME^^}\t*" > /etc/krb5kdc/kadm5.acl

echo "Installing Kerberos libraries"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y krb5-{user,kdc,admin-server,multidev} libkrb5-dev

echo "Creating KDC database"
printf "$PASSWORD\n$PASSWORD" | krb5_newrealm

echo "Creating principals for tests"
kadmin.local -q "addprinc -pw $PASSWORD administrator"

echo "Adding principal for Kerberos auth and creating keytab"
kadmin.local -q "addprinc -randkey HTTP/$HOSTNAME.$DOMAIN_NAME"
kadmin.local -q "ktadd -k /etc/httpd.keytab HTTP/$HOSTNAME.$DOMAIN_NAME"
chmod 777 /etc/httpd.keytab

echo "Restarting Kerberos KDS service"
service krb5-kdc restart

echo "Installing Apache and mod-auth-gssapi"
apt-get install -y curl apache2 libapache2-mod-auth-gssapi

echo "Add ServerName to Apache config"
grep -q -F "ServerName $HOSTNAME.$DOMAIN_NAME" /etc/apache2/apache2.conf || echo "ServerName $HOSTNAME.$DOMAIN_NAME" >> /etc/apache2/apache2.conf

echo "Deleting default virtual host file"
rm /etc/apache2/sites-enabled/000-default.conf
rm /etc/apache2/sites-available/000-default.conf
rm /etc/apache2/sites-available/default-ssl.conf

echo "Create website directory structure and pages"
mkdir -p /var/www/example.com/public_html
chmod -R 755 /var/www
echo "<html><head><title>Title</title></head><body>body mesage</body></html>" > /var/www/example.com/public_html/index.html

echo "Create virtual host files"
cat > /etc/apache2/sites-available/example.com.conf << EOL
<VirtualHost *:80>
    ServerName $HOSTNAME.$DOMAIN_NAME
    ServerAlias $HOSTNAME.$DOMAIN_NAME
    DocumentRoot /var/www/example.com/public_html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Directory "/var/www/example.com/public_html">
        AuthType GSSAPI
        AuthName "GSSAPI Single Sign On Login"
        Require user administrator@${DOMAIN_NAME^^}
        GssapiCredStore keytab:/etc/httpd.keytab  
    </Directory>
</VirtualHost>
EOL

echo "Enabling virtual host site"
a2ensite example.com.conf
service apache2 restart

echo "Getting ticket for Kerberos user"
echo -n "$PASSWORD" | kinit "administrator@${DOMAIN_NAME^^}"

echo "Try out the curl connection"
CURL_OUTPUT=$(curl --negotiate -u : "http://$HOSTNAME.$DOMAIN_NAME")

if [ "$CURL_OUTPUT" != "<html><head><title>Title</title></head><body>body mesage</body></html>" ]; then
    echo -e "ERROR: Did not get success message:\nActual Output:\n$CURL_OUTPUT"
else
    echo -e "SUCCESS: Apache site built and set for Kerberos auth\nActual Output:\n$CURL_OUTPUT"
fi
