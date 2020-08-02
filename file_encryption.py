# %load file_encryption.py
import nacl.public, nacl.encoding
import os
import stat
import gzip

# raise if file or dir has wrong permission
def assert_permissions(name, permission='rw-------'):
    message = f"Permission of '{name}' must be '{permission}'. "\
               "See 'chmod' for help"
    assert stat.filemode(os.stat(name).st_mode)[1:] == permission, message

def create_keys(fullname):
    ''' Create secret and public keys for nacl
    
        The keys are stored in path in hexencoding where
        path,name = os.split(fullname)
        
        If path does not exist, raise an error
        If path has wrong permissions, raise an error:
        Only onwner can read,write or execute path (i.e. chmod og-rwx u=rwx path)
        
        If fullname exists, raise an error
        
        The permissions of the resulting secret keyfile is og-rwx
        (Only owner can read,write or execute secret keyfile)
    '''
    
    path,name = os.path.split(fullname)
    pub_name = fullname+'.pub'
    
    # path must exist with permissions 'rwx------'
    assert os.path.exists(path), f"Path '{path}' does not exist"
    assert_permissions(path,'rwx------')
    
    # fullname must not exist
    assert not os.path.exists(fullname), f"keyfile: '{fullname}' exists already"
    
    with open(fullname,'wb') as secret_file, open(pub_name,'wb') as public_file:
        key = nacl.public.PrivateKey.generate()
        
        secret_file.write(key.encode(nacl.encoding.HexEncoder))
        public_file.write(key.public_key.encode(nacl.encoding.HexEncoder))
    
    # set permission 'rw-------' to secret_file
    os.chmod(fullname,0o600)

def read_secret_key(fullname):
    ''' Read a private key for nacl from fullname.
        The path and the fullname must have the right permissions, og-rwx
        (Only user can read,write or execute secret key)
    '''
    
    # fullname must exist with permissions 'rw-------'
    assert os.path.exists(fullname), f"File '{fullpath}' does not exist"
    assert_permissions(fullname,'rw-------')
        
    path,name = os.path.split(fullname)
    
    # path must exist with permissions 'rwx------'
    assert_permissions(path,'rwx------')
    
    with open(fullname,'rb') as f:
        key = nacl.public.PrivateKey(f.read(),encoder=nacl.encoding.HexEncoder)
        
    return key

def read_public_key(fullname):
    ''' Read a public key for nacl from fullname'''
    
    with open(fullname,'rb') as f:
        key = nacl.public.PublicKey(f.read(),encoder=nacl.encoding.HexEncoder)
    
    return key

def create_hexvalues_of_keypair():
    '''Create a secret key and return the corresponding hex-values i.e. to store in KeePassX'''
    sk = nacl.public.PrivateKey.generate()
    sk_hex = sk.encode(encoder=nacl.encoding.HexEncoder)
    pk_hex = sk.public_key.encode(encoder=nacl.encoding.HexEncoder)
    return (sk_hex,pk_hex)

def secret_key_from_hex(value):
    '''Create secret key from value stored in hexencoding i.e. in KeePassX'''
    return nacl.public.PrivateKey(value,encoder=nacl.encoding.HexEncoder)

def public_key_from_hex(value):
    '''Create public key from value stored in hexencoding i.e. in KeePassX'''
    return nacl.public.PublicKey(value,encoder=nacl.encoding.HexEncoder)

def encrypt(sk,pk,f_in_name,f_out_name):
    ''' encrypt f_in_name to f_out_name using nacl with 
        secret key sk and public key pk. If f_out_name
        ends with '.gz', use gzip
    '''
    # use gzip?
    gzipped = os.path.splitext(f_out_name)[1] == '.gz'
    open_out = gzip.open if gzipped else open
    
    with open(f_in_name,'rb') as f_in, open_out(f_out_name,'wb') as f_out:
        f_out.write(nacl.public.Box(sk,pk).encrypt(f_in.read()))


def decrypt(sk,pk,f_in_name,f_out_name):
    ''' decrypt f_in_name to f_out_name using nacl with
        secret key sk und public key pk. If f_in_name ends
        with '.gz' use gzip
    '''
    # use gzip?
    gzipped = os.path.splitext(f_in_name)[1] == '.gz'
    open_in = gzip.open if gzipped else open
    
    with open_in(f_in_name,'rb') as f_in, open(f_out_name,'wb') as f_out:
        f_out.write(nacl.public.Box(sk,pk).decrypt(f_in.read()))
