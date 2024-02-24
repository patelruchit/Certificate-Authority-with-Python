from cryptography.hazmat.primitives.asymmetric import rsa                        # Using RSA to create the Private Key
from cryptography.hazmat.primitives import serialization                         # To serialize keys i.e., to convert them to a readable format from bytes. 
from cryptography import x509                                                    # To create TLS certificates
from cryptography.x509 import oid                                                # To create the subject and issuer parameters
from cryptography.hazmat.primitives import hashes                                # To call the hash functions available with cryptography
import datetime                                                                  # For providing validity of the certs. 
from cryptography.hazmat.backends import default_backend                         # To check the default backend method available on the machine (OpenSSL, )

#Create PrivateKey
keysize = int(input('Enter the key size for private key: 1024, 2048 or 4096: '))
privatekey = rsa.generate_private_key(public_exponent= 65537, key_size=keysize)          # Note that the private key created is type: Bytes and needs to be serialized in order to write or see the contents


#Choose the passphrase for the privatekey encryption.
passphrase = input('Provide your passphrase for key encryption : ')

'''
#Converting the key to PEM, PEM with encryption or DER
pem_enc = privatekey.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))  #Check what are the types of encoding available
pem = privatekey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
'''

#Serializing the priviate key and writing it to the disk with password encryption.
with open('/Path_Provide_here/PrivateKeyenc.pem', 'wb') as keytodisk:
    keytodisk.write(privatekey.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.BestAvailableEncryption(b'{passphrase}'),
        ))

#Create self-singed certificate from the privatekey
    
# Creating the subject and Issuer details which will be the same for the Root CA    
#Gathering the details for subject and issuer as inputs. 
CommonName = input('Enter the common name: ')
Country = input ('Country code in two letters: ')
Province = input ('Province name in two letters: ')
OrgName = input ('Enter the Org. Name: ')

#Storing the data in the subject and issuer vars which are going to be identical, thus separated by =
subject = issuer = x509.Name([
    x509.NameAttribute(oid.NameOID.COMMON_NAME, CommonName),
    x509.NameAttribute(oid.NameOID.COUNTRY_NAME, Country),
    x509.NameAttribute(oid.NameOID.STATE_OR_PROVINCE_NAME, Province),
    x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, OrgName),
])

# Certing the certificate. Note the the var: cert once the certificatebuilder runs, will be in bytes format. Thus, when writing to the disk, it needs to be serialized. 
cert = x509.CertificateBuilder(
    ).issuer_name(issuer                                                                                #Calling the issuer declared above
    ).subject_name(subject                                                                              #Calling the subject declared above
    ).not_valid_before(time=datetime.datetime.now(datetime.timezone.utc)                                #Setting the validity with datetime module 
    ).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7305)      
    ).public_key(privatekey.public_key()                                                                #Calling to create the publickey from the private key
    ).serial_number(x509.random_serial_number()                                                         #Using x509 random serial number creator for setting the serial number
    ).add_extension(x509.BasicConstraints(ca=True, path_length=2),critical=True                         #Adding Basic Contraints extension
    ).sign(private_key=privatekey, algorithm=hashes.SHA256()                                            #
    )


#Write the Root Cert to disk
with open('/Path_Provide_here/RootCert.pem', 'wb') as wrroot:
    wrroot.write(cert.public_bytes(serialization.Encoding.PEM))

'''
#To check on the backend used by the machine
from cryptography.hazmat.backends import default_backend

# Get the default backend
backend = default_backend()

# Print out the name of the backend being used
print("Using backend:", backend)
'''
