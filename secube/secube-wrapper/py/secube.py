from ctypes import *
import time, sys, os

# L0 constants

SE3_COMM_BLOCK = 512
SE3_COMM_N = 16
SE3_MAGIC_SIZE = 32
SE3_HELLO_SIZE = 32
SE3_SERIAL_SIZE = 32

SE3_MAX_PATH=256

SE3_OK = 0
SE3_ERR_HW = 0xF001
SE3_ERR_COMM = 0xF002
SE3_ERR_BUSY = 0xF003
SE3_ERR_STATE = 0xF004
SE3_ERR_CMD = 0xF005
SE3_ERR_PARAMS = 0xF006
SE3_CMD0_FACTORY_INIT = 1
SE3_CMD0_ECHO = 2
SE3_CMD0_L1 = 3

SE3_CMDFLAG_ENCRYPT = (1 << 15)
SE3_CMDFLAG_SIGN = (1 << 14) 

SE3_REQ_SIZE_HEADER = 16
SE3_REQDATA_SIZE_HEADER = 4
SE3_REQ_SIZE_DATA = SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER
SE3_REQDATA_SIZE_DATA = SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER

SE3_REQ_OFFSET_CMD = 0
SE3_REQ_OFFSET_CMDFLAGS = 2
SE3_REQ_OFFSET_LEN = 4
SE3_REQ_OFFSET_CMDTOKEN = 6
SE3_REQ_OFFSET_PADDING = 10
SE3_REQ_OFFSET_CRC = 14
SE3_REQ_OFFSET_DATA = 16

SE3_REQDATA_OFFSET_CMDTOKEN = 0
SE3_REQDATA_OFFSET_DATA = 4

SE3_REQ_MAX_DATA = ((SE3_COMM_BLOCK-SE3_REQ_SIZE_HEADER) + (SE3_COMM_N-2)*(SE3_COMM_BLOCK-SE3_REQDATA_SIZE_HEADER) - 8)

SE3_RESP_SIZE_HEADER = 16
SE3_RESPDATA_SIZE_HEADER = 4
SE3_RESP_SIZE_DATA = SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER
SE3_RESPDATA_SIZE_DATA = SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER

SE3_RESP_OFFSET_READY = 0
SE3_RESP_OFFSET_STATUS = 2
SE3_RESP_OFFSET_LEN = 4
SE3_RESP_OFFSET_CMDTOKEN = 6
SE3_RESP_OFFSET_CRC = 14

SE3_RESPDATA_OFFSET_CMDTOKEN = 0
SE3_RESPDATA_OFFSET_DATA = 4

SE3_RESP_MAX_DATA = ((SE3_COMM_BLOCK-SE3_REQ_SIZE_HEADER) + (SE3_COMM_N-2)*(SE3_COMM_BLOCK-SE3_REQDATA_SIZE_HEADER) - 8)

SE3_DISCO_OFFSET_MAGIC = 0
SE3_DISCO_OFFSET_SERIAL = 32
SE3_DISCO_OFFSET_HELLO = 2*32
SE3_DISCO_OFFSET_STATUS = 3*32

# L1 constants

SE3_ERR_ACCESS = 100
SE3_ERR_PIN = 101
SE3_ERR_RESOURCE = 200
SE3_ERR_EXPIRED = 201
SE3_ERR_MEMORY = 400
SE3_ERR_AUTH = 401

SE3_ACCESS_USER = 100
SE3_ACCESS_ADMIN = 1000
SE3_ACCESS_MAX = 0xFFFF

SE3_RECORD_SIZE = 32
SE3_RECORD_MAX = 2

SE3_RECORD_TYPE_ADMINPIN = 0
SE3_RECORD_TYPE_USERPIN = 1

SE3_L1_PIN_SIZE = 32
SE3_L1_KEY_SIZE = 32
SE3_L1_AUTH_SIZE = 16
SE3_L1_CRYPTOBLOCK_SIZE = 16
SE3_L1_CHALLENGE_SIZE = 32
SE3_L1_CHALLENGE_ITERATIONS = 32
SE3_L1_IV_SIZE = 16
SE3_L1_TOKEN_SIZE = 16

SE3_REQ1_OFFSET_AUTH = 0
SE3_REQ1_OFFSET_IV = 16
SE3_REQ1_OFFSET_TOKEN = 32
SE3_REQ1_OFFSET_LEN = 48
SE3_REQ1_OFFSET_CMD = 50
SE3_REQ1_OFFSET_DATA = 64
SE3_REQ1_MAX_DATA = (SE3_REQ_MAX_DATA - SE3_REQ1_OFFSET_DATA)

SE3_RESP1_OFFSET_AUTH = 0
SE3_RESP1_OFFSET_IV = 16
SE3_RESP1_OFFSET_TOKEN = 32
SE3_RESP1_OFFSET_LEN = 48
SE3_RESP1_OFFSET_STATUS = 50
SE3_RESP1_OFFSET_DATA = 64
SE3_RESP1_MAX_DATA = (SE3_RESP_MAX_DATA - SE3_RESP1_OFFSET_DATA)

SE3_CMD1_CHALLENGE = 1
SE3_CMD1_LOGIN = 2
SE3_CMD1_LOGOUT = 3
SE3_CMD1_CONFIG = 4
SE3_CMD1_KEY_EDIT = 5
SE3_CMD1_KEY_LIST = 6
SE3_CMD1_CRYPTO_INIT = 7
SE3_CMD1_CRYPTO_UPDATE = 8
SE3_CMD1_CRYPTO_LIST = 9
SE3_CMD1_CRYPTO_SET_TIME = 10

SE3_CONFIG_OP_GET = 1
SE3_CONFIG_OP_SET = 2

SE3_KEY_DATA_MAX = 2048
SE3_KEY_NAME_MAX = 32
SE3_KEY_FINGERPRINT_SIZE = 32
SE3_KEY_SALT_SIZE = 32

SE3_KEY_OP_INSERT = 1
SE3_KEY_OP_DELETE = 2
SE3_KEY_OP_UPSERT = 3

SE3_ALGO_INVALID = 0xFFFF
SE3_SESSION_INVALID = 0xFFFFFFFF
SE3_KEY_INVALID = 0xFFFFFFFF

SE3_ALGO_AES = 0
SE3_ALGO_SHA256 = 1
SE3_ALGO_HMACSHA256 = 2
SE3_ALGO_AES_HMACSHA256 = 3
SE3_ALGO_MAX = 8

SE3_CRYPTO_FLAG_FINIT = (1 << 15)
SE3_CRYPTO_FLAG_RESET = (1 << 14)
SE3_CRYPTO_FLAG_SETIV = SE3_CRYPTO_FLAG_RESET
SE3_CRYPTO_FLAG_SETNONCE = (1 << 13)
SE3_CRYPTO_FLAG_AUTH = (1 << 12)

SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA = 16
SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA = 16
SE3_CRYPTO_MAX_DATAIN = (SE3_REQ1_MAX_DATA - SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA)
SE3_CRYPTO_MAX_DATAOUT = (SE3_RESP1_MAX_DATA - SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA)

SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE = 16

SE3_CRYPTO_TYPE_BLOCKCIPHER = 0
SE3_CRYPTO_TYPE_STREAMCIPHER = 1
SE3_CRYPTO_TYPE_DIGEST = 2
SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH = 3
SE3_CRYPTO_TYPE_OTHER = 0xFFFF

SE3_FEEDBACK_ECB = 1
SE3_FEEDBACK_CBC = 2
SE3_FEEDBACK_OFB = 3
SE3_FEEDBACK_CTR = 4
SE3_FEEDBACK_CFB = 5

SE3_DIR_SHIFT = 8
SE3_DIR_ENCRYPT = (1 << SE3_DIR_SHIFT)
SE3_DIR_DECRYPT = (2 << SE3_DIR_SHIFT)

SE3_ERROR_STRINGS={
    SE3_OK: "success",
    SE3_ERR_HW : "hardware failure",
    SE3_ERR_COMM : "communication error",
    SE3_ERR_BUSY : "device locked by another process",
    SE3_ERR_STATE : "invalid state for this operation",
    SE3_ERR_CMD : "command does not exist",
    SE3_ERR_PARAMS: "parameters are not valid",
    SE3_ERR_ACCESS : "insufficient privileges",
    SE3_ERR_PIN : "pin rejected",
    SE3_ERR_RESOURCE : "resource not found",
    SE3_ERR_EXPIRED : "resource expired",
    SE3_ERR_MEMORY : "no more space to allocate resource"
}
SE3_CRYPTO_TYPE_STRINGS={
    SE3_CRYPTO_TYPE_BLOCKCIPHER : "BlockCipher",
    SE3_CRYPTO_TYPE_STREAMCIPHER : "StreamCipher",
    SE3_CRYPTO_TYPE_DIGEST : "Digest",
    SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH : "AuthenticatedBlockCipher",
    SE3_CRYPTO_TYPE_OTHER : "Other"
}



# TODO linux/windows

if sys.platform.startswith('cygwin') or sys.platform.startswith('win32'):
    os_type='windows'
elif sys.platform.startswith('linux'):
    os_type='linux'
elif sys.platform.startswith('darwin'):
    os_type='mac'
else:
    os_type=''
is_x64=(sys.maxsize > 2**32)

DLLBASENAME="secube"
DLLNAME={
    ('windows',False) : "%s-x86.dll"%DLLBASENAME,
    ('windows',True) : "%s-x64.dll"%DLLBASENAME,
    ('linux',False) : "%s-x86.so"%DLLBASENAME,
    ('linux',True) : "%s-x64.so"%DLLBASENAME,
    ('mac',False) : "%s-dw-x86.so"%DLLBASENAME,
    ('mac',True) : "%s-dw-x64.so"%DLLBASENAME
}

if os_type=='windows':
    c_fschar=c_wchar
    c_fschar_p=c_wchar_p
else:
    c_fschar=c_char
    c_fschar_p=c_char_p
    
# DLL initialization
if not (os_type, is_x64) in DLLNAME:
    raise Exception("Platform not supported")

dll = CDLL(DLLNAME[(os_type, is_x64)])

dll.se3_device_alloc.restype=POINTER(c_char)
dll.se3_disco_it_alloc.restype=POINTER(c_char)
dll.se3_disco_it_get_device_info.restype=POINTER(c_char)
dll.se3_device_info_get_path.restype=POINTER(c_fschar)
dll.se3_device_info_get_serialno.restype=POINTER(c_ubyte)
dll.se3_device_info_get_hello_msg.restype=POINTER(c_ubyte)
dll.se3_device_info_get_status.restype=c_uint
dll.se3_session_alloc.restype=POINTER(c_char)
dll.se3_session_logged_in.restype=c_uint
dll.se3_key_alloc.restype=POINTER(c_char)
dll.se3_key_get_id.restype=c_uint
dll.se3_key_get_validity.restype=c_uint
dll.se3_key_get_data_size.restype=c_uint
dll.se3_key_get_name_size.restype=c_uint
dll.se3_key_get_fingerprint.restype=POINTER(c_ubyte)
dll.se3_key_get_data.restype=POINTER(c_ubyte)
dll.se3_key_get_name.restype=POINTER(c_char)
dll.se3_algo_alloc.restype=POINTER(c_char)
dll.se3_algo_get_name.restype=POINTER(c_char)
dll.se3_algo_get_block_size.restype=c_uint
dll.se3_algo_get_key_size.restype=c_uint
dll.se3_algo_get_type.restype=c_uint

dll.L0_TXRX.restype=c_ushort
dll.L0_echo.restype=c_ushort
dll.L0_factoryinit.restype=c_ushort
dll.L0_open.restype=c_ushort
dll.L0_discover_serialno.restype=c_bool
dll.L0_discover_next.restype=c_bool

dll.L1_login.restype=c_ushort
dll.L1_set_admin_PIN.restype=c_ushort
dll.L1_set_user_PIN.restype=c_ushort
dll.L1_logout.restype=c_ushort
dll.L1_key_list.restype=c_ushort
dll.L1_key_edit.restype=c_ushort
dll.L1_crypto_init.restype=c_ushort
dll.L1_crypto_update.restype=c_ushort
dll.L1_crypto_set_time.restype=c_ushort
dll.L1_get_algorithms.restype=c_ushort
    
    
class SEcubeError(Exception):
    def __init__(self, code):
        msg=SE3_ERROR_STRINGS.get(code, "Unknown")
        super(Exception, self).__init__("SEcube API error %d (%s)"%(code,msg))
        self.code=code
    
    
class SEcubeDeviceInfo:
    def __init__(self, serialno, path, hello, status):
        self.serialno=serialno
        self.path=path
        self.hello=hello
        self.status=status
    
    def __repr__(self):
        return ("SEcubeDeviceInfo(path=%s, serialno="+4*"%02x"+"...)")%((self.path,) +tuple(self.serialno[:4]))

class SEcubeKey:
    def __init__(self, id=0, name="", validity=-365*24*3600, fingerprint=None, data=None):
        self.id=id
        self.name=name
        self.data=data
        self.data_size=0
        if self.data is not None:
            self.data_size=len(self.data)
        self.validity=validity
        self.fingerprint=fingerprint
        if self.validity<0:
            self.validity=int(time.time())-self.validity
    
    def __repr__(self):
        return "SEcubeKey(id=%d, name=%s, validity=%d)"%(self.id, self.name, self.validity)
        
    def __str__(self):
        return self.name
    
    def __len__(self):
        return self.data_size
        
    def __int__(self):
        return self.id
       
def _read_string(pstr, max_length):
    try:
        count=0
        for c in pstr[:max_length]:
            if c==0: break
            count+=1
        return pstr[:count].decode("utf-8")
    except:
        return ""
       
def _read_key(ckeys, index, read_data=False):
    id=dll.se3_key_get_id(ckeys, c_uint(index))
    validity=dll.se3_key_get_validity(ckeys, c_uint(index))
    name_size=dll.se3_key_get_name_size(ckeys, c_uint(index))
    
    if name_size<SE3_KEY_NAME_MAX:
        name=dll.se3_key_get_name(ckeys, c_uint(index))
        name=_read_string(name, name_size)
    else:
        name=""
    
    cfingerprint=dll.se3_key_get_fingerprint(ckeys, c_uint(index))
    fingerprint=bytes(cfingerprint[:SE3_KEY_FINGERPRINT_SIZE])
    
    data=None
    data_size=dll.se3_key_get_data_size(ckeys, c_uint(index))
    if read_data:
        data=dll.se3_key_get_data(ckeys, c_uint(index))
        data=bytes(data[:data_size])
    key = SEcubeKey(id=id, name=name, validity=validity, fingerprint=fingerprint, data=data)
    key.data_size=data_size
    return key

def _write_key(ckeys, index, key, cdata=None):
    dll.se3_key_set_id(ckeys, c_uint(index), c_uint(key.id))
    dll.se3_key_set_validity(ckeys, c_uint(index), c_uint(key.validity))
    cname=(SE3_KEY_NAME_MAX*c_char)(*([0]*SE3_KEY_NAME_MAX))
    utf8name=key.name.encode("utf-8")
    name_size=min(len(utf8name), SE3_KEY_NAME_MAX)
    cname[:name_size]=utf8name[:name_size]
    dll.se3_key_set_name(ckeys, c_uint(index),
        c_uint(name_size),
        cast(cname, POINTER(c_char)))
    if cdata is not None:
        dll.se3_key_set_data(ckeys, c_uint(index),
            c_uint(len(cdata)),
            cast(cdata, POINTER(c_ubyte)))
    else:
        dll.se3_key_set_data(ckeys, c_uint(index),
            c_uint(0), POINTER(c_ubyte)())
    
class SEcubeAlgorithm:
    def __init__(self, type=SE3_CRYPTO_TYPE_OTHER, name="", block_size=0, key_size=0):
        self.type=type
        self.name=name
        self.block_size=block_size
        self.key_size=key_size
    
    def __repr__(self):
        stype=SE3_CRYPTO_TYPE_STRINGS.get(self.type, "Unknown")
        return "SEcubeAlgorithm(type=%s, name=%s)"%(stype, self.name)
    
def _read_algo(calgos, index):
    type=dll.se3_algo_get_type(calgos, c_uint(index))
    name=dll.se3_algo_get_name(calgos, c_uint(index))
    name=_read_string(name, SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE)
    block_size=dll.se3_algo_get_block_size(calgos, c_uint(index))
    key_size=dll.se3_algo_get_key_size(calgos, c_uint(index))
    return SEcubeAlgorithm(type=type, name=name, block_size=block_size, key_size=key_size)
    
class SEcube:
    @staticmethod
    def discover():
        devices=[]
        it=dll.se3_disco_it_alloc()
        dll.L0_discover_init(it)
        while dll.L0_discover_next(it):
            info=dll.se3_disco_it_get_device_info(it)
            serialno=dll.se3_device_info_get_serialno(info)
            path=dll.se3_device_info_get_path(info)
            hello=dll.se3_device_info_get_hello_msg(info)
            status=dll.se3_device_info_get_status(info)
            devices.append(SEcubeDeviceInfo(
                bytes(serialno[:SE3_SERIAL_SIZE]),
                cast(path, c_fschar_p).value,
                bytes(hello[:SE3_HELLO_SIZE]),
                status))
        dll.se3_free(it)
        return devices
    
    def __init__(self, dev_info=None):
        self.session=None
        if dev_info is None:
            devices = SEcube.discover()
            if len(devices) == 0:
                raise Exception("No SEcube device found")
            dev_info=devices[0]
        self.dev=dll.se3_device_alloc()
        
        # create a se3_device_info structure, fill path and serial
        disco_it=dll.se3_disco_it_alloc()
        info=dll.se3_disco_it_get_device_info(disco_it)
        info_path=dll.se3_device_info_get_path(info)
        info_serialno=dll.se3_device_info_get_serialno(info)
        for i in range(len(dev_info.path)):
            info_path[i]=dev_info.path[i]
        info_path[len(dev_info.path)]=b'\0'
        for i in range(SE3_SERIAL_SIZE):
            info_serialno[i]=dev_info.serialno[i]
        
        # open device
        r = dll.L0_open(self.dev, info, 1000)
        dll.se3_free(disco_it)
        
        if SE3_OK != r:
            dll.se3_free(self.dev)
            self.dev=None
            raise SEcubeError(r)
    
    def close(self):
        if self.dev is None:
            return
        dll.L0_close(self.dev)
        dll.se3_free(self.dev)
        self.dev=None
    
    def echo(self, data):
        if len(data) > SE3_REQ_MAX_DATA:
            raise SEcubeError(SE3_ERR_PARAMS)
        cdata_in = (len(data)*c_ubyte)(*data)
        cdata_out = (len(data)*c_ubyte)()
        r = dll.L0_echo(self.dev,
            cast(cdata_in, POINTER(c_ubyte)),
            c_ushort(len(data)),
            cast(cdata_out, POINTER(c_ubyte)))
        if SE3_OK != r:
            raise SEcubeError(r)
        return bytes(cdata_out)
    
    def factoryinit(self, serialno):
        if len(serialno)!=32:
            raise SEcubeError(SE3_ERR_PARAMS)
        cserial=(SE3_SERIAL_SIZE*c_ubyte)(*serialno)
        r=dll.L0_factoryinit(self.dev, cast(cserial, POINTER(c_ubyte)))
        if SE3_OK != r:
            raise SEcubeError(r)
     
    def login(self, pin, access=SE3_ACCESS_USER):
        if isinstance(pin, str):
            pin=pin.encode("utf-8")
        if (not isinstance(pin, bytes)) or len(pin)>32:
            raise SEcubeError(SE3_ERR_PARAMS)
        cpin=(SE3_L1_PIN_SIZE*c_ubyte)(*([0]*32))
        cpin[:len(pin)]=pin
        self.session=dll.se3_session_alloc()
        r=dll.L1_login(
            self.session,
            self.dev,
            cast(cpin, POINTER(c_ubyte)),
            c_ushort(access))
        if SE3_OK != r:
            dll.se3_free(self.session)
            self.session=None
            raise SEcubeError(r)
    
    def logout(self):
        if self.session is None:
            return
        for i in range(3):
            r = dll.L1_logout(self.session)
            if SE3_OK == r:
                break
        dll.se3_free(self.session)
        self.session=None
        if SE3_OK != r:
            raise SEcubeError(r)
    
    def _set_pin(self, func, pin):
        if isinstance(pin, str):
            pin=pin.encode("utf-8")
        cpin=(SE3_L1_PIN_SIZE*c_ubyte)(*([0]*32))
        cpin[:len(pin)]=pin
        
        r = func(self.session, cast(cpin, POINTER(c_ubyte)))
        if SE3_OK != r:
            raise SEcubeError(r)
    
    def set_admin_PIN(self, pin):
        self._set_pin(dll.L1_set_admin_PIN, pin)
    
    def set_user_PIN(self, pin):
        self._set_pin(dll.L1_set_user_PIN, pin)
        
    def crypto_init(self, algorithm, mode, key_id):
        csid=(1*c_uint)()
        r = dll.L1_crypto_init(
            self.session,
            c_ushort(algorithm),
            c_ushort(mode),
            c_uint(key_id),
            cast(csid, POINTER(c_uint)))
        if SE3_OK != r:
            raise SEcubeError(r)
        return csid[0]
    
    def crypto_update(self, sess_id, flags, data1, data2):
        if data1 is None:
            cdata1=POINTER(c_ubyte)()
            data1_len=0
        else:
            cdata1=(len(data1)*c_ubyte)(*data1)
            data1_len=len(data1)
        if data2 is None:
            cdata2=POINTER(c_ubyte)()
            data2_len=0
        else:
            cdata2=(len(data2)*c_ubyte)(*data2)
            data2_len=len(data2)
        cdataout_len=(1*c_ushort)()
        cdataout=(SE3_CRYPTO_MAX_DATAOUT*c_ubyte)()
        r=dll.L1_crypto_update(
            self.session,
            c_uint(sess_id),
            c_ushort(flags),
            c_ushort(data1_len),
            cast(cdata1, POINTER(c_ubyte)),
            c_ushort(data2_len),
            cast(cdata2, POINTER(c_ubyte)),
            cast(cdataout_len, POINTER(c_ushort)),
            cast(cdataout, POINTER(c_ubyte)))
        
        if SE3_OK != r:
            raise SEcubeError(r)
        if cdataout_len[0]>SE3_CRYPTO_MAX_DATAOUT:
            raise SEcubeError(SE3_ERR_COMM)
        return bytes(cdataout[:cdataout_len[0]])
    
    def crypto_set_time(self, devtime):
        
        r=dll.L1_crypto_set_time(self.session, c_uint(devtime))
        
        if SE3_OK != r:
            raise SEcubeError(r)
            
    def get_algorithms(self):
        ret=[]
        skip=0
        max_algos=32
        algos=dll.se3_algo_alloc(c_uint(max_algos))
        ccount=(1*c_ushort)()
        success=False
        r=SE3_OK
        nit=0
        while not success and nit<100:
            r = dll.L1_get_algorithms(self.session, c_ushort(skip), c_ushort(max_algos), 
                algos, cast(ccount, POINTER(c_ushort)))
            if SE3_OK != r:
                break
            else:
                if ccount[0]==0:
                    success=True
                else:
                    for index in range(ccount[0]):
                        ret.append(_read_algo(algos, index))
                    nit+=1
                    skip+=ccount[0]
        dll.se3_free(algos)
        if not success:
            if SE3_OK != r:
                raise SEcubeError(r)
            else:
                raise SEcubeError(SE3_ERR_COMM)
        return ret
    
    def key_list(self, salt=None):
        ret=[]
        skip=0
        max_keys=128
        keys=dll.se3_key_alloc(c_uint(max_keys))
        ccount=(1*c_ushort)()
        if salt is None:
            csalt=POINTER(c_ubyte)()
        else:
            csalt=(SE3_KEY_SALT_SIZE*c_ubyte)(*salt)
        success=False
        r=SE3_OK
        nit=0
        while not success and nit<1000:
            r = dll.L1_key_list(self.session, c_ushort(skip), c_ushort(max_keys), 
                cast(csalt, POINTER(c_ubyte)), keys, cast(ccount, POINTER(c_ushort)))
            if SE3_OK != r:
                break
            else:
                if ccount[0]==0:
                    success=True
                else:
                    for index in range(ccount[0]):
                        ret.append(_read_key(keys, index))
                    nit+=1
                    skip+=ccount[0]
        dll.se3_free(keys)
        if not success:
            if SE3_OK != r:
                raise SEcubeError(r)
            else:
                raise SEcubeError(SE3_ERR_COMM)
        return ret
    
    def key_edit(self, op, key):
        ckey=dll.se3_key_alloc(c_uint(1))
        cdata=None
        if key.data is not None:
            cdata=(len(key.data)*c_ubyte)(*key.data)
        _write_key(ckey, 0, key, cdata)
        r = dll.L1_key_edit(self.session, c_ushort(op), ckey)
        dll.se3_free(ckey)
        
        if SE3_OK != r:
            raise SEcubeError(r)
    

if __name__=="__main__":
    print("NOW %d"%int(time.time()))
    devs=SEcube.discover()
    print("Found %d devices"%len(devs))
    for dev in devs:
        print(dev)
    
    if len(devs)>0:
        cube=SEcube(devs[0])
        try:
            print(cube.echo("Hello SEcube".encode("utf-8")))
            cube.login("ciao")
            keys=cube.key_list()
            print("Found %d keys"%len(keys))
            for key in keys:
                print(key)
            algorithms=cube.get_algorithms()
            print("Found %d algorithms"%len(algorithms))
            for algo in algorithms:
                print(algo)
        except:
            import traceback
            traceback.print_exc()
        cube.logout()
        cube.close()

    
