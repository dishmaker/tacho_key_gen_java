# Tachograph Key Tool

## Docs

[Key Gen Tool User Manual](https://dtc.jrc.ec.europa.eu/iot_doc/Sample%20Key%20Generation%20Tool%20User%20Manual%20v1.0.pdf)

[JRC Tachograph](https://dtc.jrc.ec.europa.eu/dtc_smart_tachograph.php.html)


## Building

The Tachograph Key Tool project uses Maven to manage the build process. In order to build, Maven and JDK 8 have to be installed. It is also required that Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files have been installed. Run the following command to build the tool:

```
mvn clean install
```

The output of the build is an executable jar file. 

# Executing

The Tachograph Key Tool is a Java command line application. It requires Java 8 with Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files installed. 
The tool depends on the Bouncy Castle JCE provider. The required bcprov-jdk15on-1.56.jar needs to be in the same folder as the executable jar. Refer to the install folder for an example installation.
Use the following command line to run the tool and show to command line options (the version number may be different):

```
java -jar tachograph-keytool-1.0.0.jar
```

The st.bat is added to simplify command line usage. Use the following commands to show details on the supported functions:

```
st generate
st create
st link
st sign
st verify
st derive
st encrypt
```

## Examples

```
st generate ec keyfilename secp521r1
st create equipment vu_ma name keyfilename.pkcs8 01 12 24 AA
```


```
st generate ec driver_card_1 secp521r1
st create equipment driver_card_ma drivercard_1 driver_card_1.pkcs8 0x02000131 4 17 0x41 2008-01-01T12:00:00 2030-01-01T12:00:00
```

## Usage

```
Usage:
generate aes <name> <size>
       To generate an AES secret key, and store it in a binary file.
generate ec <name> <curve>
       To generate an EC key pair, and store the private key in a PKCS#8 file.
  name - the name of the file to be created
  size - the size in bits of the secret key to be generated (128, 192, or 256)
  curve - the standard name of the elliptic curve parameters to be used:
	secp256r1
	secp384r1
	secp521r1
	brainpoolp256r1
	brainpoolp384r1
	brainpoolp512r1

create ca <catype> <name> <keyname> <nationnumeric> <nationalpha> <serialnumber> <additionalinfo> <caidentifier> [<effectivedate> [<expirationdate>]]
       To create a self-signed certificate with a certification authority KID.
create equipment <equipmenttype> <name> <keyname> <serialnumber> <month> <year> <manufacturercode> [<effectivedate> [<expirationdate>]]
       To create a self-signed certificate with an equipment extended serial number.
create request <requesttype> <name> <keyname> <serialnumber> <month> <year> <manufacturercode> [<effectivedate> [<expirationdate>]]
       To create a self-signed certificate with a certificate request ID.
  catype - one of the following options:
	erca
	msca_card
	msca_vu_egf
  equipmenttype - one of the following options:
	driver_card_ma
	driver_card_sign
	workshop_card_ma
	workshop_card_sign
	control_card_ma
	company_card_ma
	vu_ma
	vu_sign
	egf_ma
  requesttype - one of the following options:
	vu_ma
	vu_sign
  name - the name of the certificate file to be created
  keyname - the name of the PKCS#8 file containing the key to be certified
  nationnumeric - a numerical identifier of the nation
  nationalpha - a country code of up to three characters
  serialnumber - the key or equipment serial number
  month - the month to be encoded in the extended serial number or request ID
  year - the year to be encoded in the extended serial number or request ID
  additionalinfo - the additional info field
  caidentifier - the CA identifier
  manufacturercode - the manufacturer code
  effectivedate - the certificate effective date and time in ISO 8601 format (e.g. 2018-01-01T12:00:00)
  expirationdate - the certificate expiration date and time in ISO 8601 format (e.g. 2018-01-01T12:00:00)

link <key> <currentcertificate> <nextcertificate> <name>
       To create and sign an ERCA link certificate.
  key - the name of the file containing the current ERCA private key
  currentcertificate - the name of the file containing the current ERCA certificate
  nextcertificate - the name of the file containing the next ERCA certificate
  name - the file name of the link certificate to be created.

sign <selfsignedcertificate> <caprivatekey> <cacertificate> <name>
       To sign a previously generated certificate.
  selfsignedcertificate - the name of the file containing the self-signed certificate to be signed
  caprivatekey - the name of the file containing the CA private key
  cacertificate - the name of the file containing the CA certificate
  name - the name of the certificate file to be created.

verify <certificate> <cacertificate>
       To verify a previously generated certificate.
  certificate - the name of the file containing the certificate to be verified
  cacertificate - the name of the file containing the CA certificate.

derive dsrc <name> <dsrcmk> <serialnumber> <month> <year> <manufacturercode>
derive dsrc <name> <dsrcmk> <extendedserialnumber>
       To derive vehicle unit specific DSRC encryption and authentication keys.
       The encryption key will be stored in a file named <name>-enc.bin
       The authentication key will be stored in a file named <name>-mac.bin
derive msmk <name> <msmkvu> <msmkwc>
       To derive the Motion Sensor Master Key from the vehicle unit and workshop card parts.
       The MSMK key will be stored in a file named <name>.bin
derive msik <name> <msmk>
       To derive the Identification Key from a Motion Sensor Master Key.
       The MSIK key will be stored in a file named <name>.bin
  name - the base name for the output files
  dsrcmk - the name of the file containing the DSRC master key
  msmkvu - the name of the file containing the VU part of the MSMK
  msmkwc - the name of the file containing the WC part of the MSMK
  msmk - the name of the file containing the MSMK
  serialnumber - the serial number of the vehicle unit
  month - the month
  year - the year
  manufacturercode - the manufacturer code
  extendedserialnumber - the extended serial number of the vehicle unit (16 hexadecimal digits)

encrypt ms <name> <msmk> <serialnumber> <month> <year> <manufacturercode>
encrypt ms <name> <msmk> <extendedserialnumber>
       To encrypt a motion sensor extended serial number with an identification key.
       The identification key wil be derived from the  motion sensor master key.
       The result will be stored in a file named <name>-esn-enc.bin
encrypt pk <name> <msmk> <pk>
       To encrypt a pairing key.
       The encrypted pairing key will be stored in a file named <name>-pk-enc.bin
  name - the base name for the output file
  msmk - the name of the file containing the motion sensor master key
  serialnumber - the serial number of the motion sensor
  month - the month
  year - the year
  manufacturercode - the manufacturer code
  extendedserialnumber - the extended serial number of the motion sensor (16 hexadecimal digits)
  pk - the name of the file containing the pairing key

```
