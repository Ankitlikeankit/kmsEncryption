import json
import base64 
import logging 
import boto3
import os
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

def retrieve_cmk(desc):
    """Retrieve an existing KMS CMK based on its description

    :param desc: Description of CMK specified when the CMK was created
    :return Tuple(KeyId, KeyArn) where:
        KeyId: CMK ID
        KeyArn: Amazon Resource Name of CMK
    :return Tuple(None, None) if a CMK with the specified description was
    not found
    """

    # Retrieve a list of existing CMKs
    # If more than 100 keys exist, retrieve and process them in batches
    kms_client = boto3.client('kms')
    try:
        response = kms_client.list_keys()
    except ClientError as e:
        logging.error(e)
        return None, None

    done = False
    while not done:
        for cmk in response['Keys']:
            # Get info about the key, including its description
            try:
                key_info = kms_client.describe_key(KeyId=cmk['KeyArn'])
            except ClientError as e:
                logging.error(e)
                return None, None

            # Is this the key we're looking for?
            if key_info['KeyMetadata']['Description'] == desc:
                return cmk['KeyId'], cmk['KeyArn']

        # Are there more keys to retrieve?
        if not response['Truncated']:
            # No, the CMK was not found
            logging.debug('A CMK with the specified description was not found')
            done = True
        else:
            # Yes, retrieve another batch
            try:
                response = kms_client.list_keys(Marker=response['NextMarker'])
            except ClientError as e:
                logging.error(e)
                return None, None

    # All existing CMKs were checked and the desired key was not found
    return None, None

def create_data_key(cmk_id, key_spec='AES_256'):
    """Generate a data key to use when encrypting and decrypting data

    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
        'AES_128': Generate a 128-bit symmetric key
        'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
        EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
        PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """

    # Create data key
    kms_client = boto3.client('kms')
    try:
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
    except ClientError as e:
        logging.error(e)
        return None, None

    # Return the encrypted and plaintext data key
    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])


NUM_BYTES_FOR_LEN = 4
def encrypt_file(cmk_id):
    """Encrypt a file using an AWS KMS CMK

    A data key is generated and associated with the CMK.
    The encrypted data key is saved with the encrypted file. This enables the
    file to be decrypted at any time in the future and by any program that
    has the credentials to decrypt the data key.
    The encrypted file is saved to <filename>.encrypted
    Limitation: The contents of filename must fit in memory.

    :param filename: File to encrypt
    :param cmk_id: AWS KMS CMK ID or ARN
    :return: True if file was encrypted. Otherwise, False.
    """
    
    s3_client=boto3.resource('s3')
    s3_bucket_name=''
    my_bucket=s3_client.Bucket(s3_bucket_name)
    
    
    bucket_list=[]


    #put every file name of csv_input/ folder of bucket in the list
    for file in my_bucket.objects.filter(Prefix="KMS_EXAMPLE/"):
        file_name=file.key
        #print(file_name)
        if file_name.find(".txt")!=-1:
            bucket_list.append(file_name)
        

    #performs operations for every file in the the folder
    for file in bucket_list:
        x=[]
        filename=''
        x=file.split('/')
        filename=x[-1]
        obj=s3_client.Object(s3_bucket_name,file)
        data=obj.get()['Body'].read()
        print("Normal Data",data)
        print(file)
        print("File name is ",filename)
        data_key_encrypted, data_key_plaintext = create_data_key(cmk_id)
        try:
            f=Fernet(data_key_plaintext)
            #print("Encrypted data=> ",f)
            encrypt_data =f.encrypt(data)
            print("Encrypted data ",encrypt_data)
            lambda_path='/tmp/'+filename+'.encrypted'
            s3_path = "KMS_EXAMPLE/" + filename
            with open(lambda_path,'wb') as file_encrypted:
                file_encrypted.write(len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN,
                                                                      byteorder='big'))
                file_encrypted.write(data_key_encrypted)
                file_encrypted.write(encrypt_data)

        except Exception as e:
            print(e)
        s3_client.meta.client.upload_file(lambda_path, s3_bucket_name,s3_path)
    return True
    
    
def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key

    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """

    # Decrypt the data key
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        logging.error(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))
    


def decrypt_file():

    # Read the encrypted file into memory
    
    s3_client=boto3.resource('s3')
    s3_bucket_name=''
    my_bucket=s3_client.Bucket(s3_bucket_name)
    
    
    bucket_list=[]


    #put every file name of csv_input/ folder of bucket in the list
    for file in my_bucket.objects.filter(Prefix="KMS_EXAMPLE/"):
        file_name=file.key
        #print(file_name)
        if file_name.find(".txt")!=-1:
            bucket_list.append(file_name)
        

    #performs operations for every file in the the folder
    for file in bucket_list:
        x=[]
        filename=''
        x=file.split('/')
        filename=x[-1]
        obj=s3_client.Object(s3_bucket_name,file)
        file_contents=obj.get()['Body'].read()

        # The first NUM_BYTES_FOR_LEN bytes contain the integer length of the
        # encrypted data key.
        # Add NUM_BYTES_FOR_LEN to get index of end of encrypted data key/start
        # of encrypted data.
        data_key_encrypted_len = int.from_bytes(file_contents[:NUM_BYTES_FOR_LEN],
                                                byteorder='big') \
                                 + NUM_BYTES_FOR_LEN
        data_key_encrypted = file_contents[NUM_BYTES_FOR_LEN:data_key_encrypted_len]
    
        # Decrypt the data key before using it
        data_key_plaintext = decrypt_data_key(data_key_encrypted)
        print("data key plain -> ",data_key_plaintext)
        
        f = Fernet(data_key_plaintext)
        file_contents_decrypted = f.decrypt(file_contents[data_key_encrypted_len:])
        
        print("file_contents_decrypted->  ",file_contents_decrypted)
        
        
        lambda_path='/tmp/'+filename+'.decrypted'
        s3_path = "KMS_EXAMPLE/" + filename
        with open(lambda_path,'wb') as file_decrypted:
            file_decrypted.write(file_contents_decrypted)
            
        s3_client.meta.client.upload_file(lambda_path, s3_bucket_name,s3_path)

    # The same security issue described at the end of encrypt_file() exists
    # here, too, i.e., the wish to wipe the data_key_plaintext value from
    # memory.
    return True

    
def lambda_handler(event, context):
    # TODO implement
    res=retrieve_cmk("mykey")
    datakey=create_data_key(res[0], key_spec='AES_256')
    #filename =getS3path("awsgluepoc-crawford")
    #enc=encrypt_file(res[0])
    #print(datakey)
    decrypt_file()
    return {
        'statusCode': 200,
        'body': json.dumps(res)
    }
