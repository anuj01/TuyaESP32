from timeutils import RTC

import ubinascii
import ucryptolib as ucl
import ujson as json

import socket
import time

clock = RTC()

SET = 'set'
STATUS = 'status'
PROTOCOL_VERSION_BYTES_33 = b'3.3'
PROTOCOL_33_HEADER = PROTOCOL_VERSION_BYTES_33 + 12 * b"\x00"

# This is intended to match requests.json payload
# at https://github.com/codetheweb/tuyapi
payload_dict = {
  "device": {
    "status": {
      "hexByte": "0a",
      "command": {"gwId": "", "devId": "", "uid": "", "t": ""}
    },
    
    "set": {
      "hexByte": "07",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    
    "prefix": "000055aa", 
    "suffix": "0000aa55"  
  }
}

def hex2bin(x):
    return ubinascii.unhexlify(x)

def bin2hex(x):
    space = ''
    result = ''.join('%02X%s' % (y, space) for y in x)
    return result


class AESCipher():
    def __init__(self, key):
        # self.bs = 32  # 32 work fines for ON, does not work for OFF.
        # Padding different compared to js version https://github.com/codetheweb/tuyapi/
        self.bs = 16
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = ucl.aes(self.key, 1)
        crypted_text = cipher.encrypt(raw)
        return crypted_text

    def decrypt(self, enc):
        cipher = ucl.aes(self.key, 1)
        raw = cipher.decrypt(enc)
        return self._unpad(raw).decode('utf-8')

    def _pad(self, s):
        padnum = self.bs - len(s) % self.bs
        return s + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(dec):
        s = bytes(bytearray(dec))
        return s[:-ord(s[len(s)-1:])]

class TuyaDevice(object):
    def __init__(self, dev_id, address, local_key=None, dev_type=None, connection_timeout=20):
        """
        Represents a Tuya device.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            dev_type (str, optional): The device type.
                It will be used as key for lookups in payload_dict.
                Defaults to None.

        Attributes:
            port (int): The port to connect to.
        """
        self.id = dev_id
        self.address = address
        self.local_key = local_key
        self.local_key = local_key.encode('latin1')
        self.dev_type = dev_type
        self.connection_timeout = connection_timeout

        self.port = 6668  # default - do not expect caller to pass in

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this

    def _send_receive(self, payload):
        """
        Send single buffer `payload` and receive a single buffer.

        Args:
            payload(bytes): Data to send.
        """
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connection_timeout)
        s.connect((self.address, self.port))
        
        success = False
        s.send(payload)
        time.sleep(0.01)
        while not success:
            try:
                data = s.recv(1024)
                # device may send null ack (28 byte) response before a full response
                if len(data) <= 28:
                    print('received null payload (%r), fetch new one',data)
                    time.sleep(0.1)
                    data = s.recv(1024)  # try to fetch new payload
                
                success = True
                print('\nData received:%r', data)
                
            except KeyboardInterrupt as err:
                print('Keyboard Interrupt - Exiting')
                raise
            
            s.close()
            return data
            

    def generate_payload(self, command, data=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
        """
        #print('Generating payload:')
        json_data = payload_dict[self.dev_type][command]['command']
        command_hb = payload_dict[self.dev_type][command]['hexByte']
        
                   
        clock.ntp_sync()
        
        #print("json_data: ", json_data)

        if 'gwId' in json_data:
            json_data['gwId'] = self.id
        if 'devId' in json_data:
            json_data['devId'] = self.id
        if 'uid' in json_data:
            json_data['uid'] = self.id  # still use id, no seperate uid
        if 't' in json_data:
            json_data['t'] = str(clock.utcnow())  #"1626017050" 

        if data is not None:
            json_data['dps'] = data
            
        # Create byte buffer from hex data
        json_payload = json.dumps(json_data)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        json_payload = json_payload.encode('utf-8')
        
        #json_payload = b'{"devId":"52585621c4dd571b91ea","uid":"52585621c4dd571b91ea","t":"1626418169","dps":{"1":false}}'
        print('json_payload=', json_payload)
        
        #if command == SET:
        #if command == STATUS:
            # need to encrypt
        self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
        payload = self.cipher.encrypt(json_payload)
        self.cipher = None  # expect to connect and then disconnect to set new
        
        if command_hb != '0a' and command_hb != '12':
            # add the 3.3 header
            payload = PROTOCOL_33_HEADER + payload

        cipher = payload
        
        #print("cipher:\n",cipher)

        assert len(cipher) <= 0xff
        
        payload_hex_len = '%x' % (len(cipher) + 8)  # TODO this assumes a single byte 0-255 (0x00-0xff)
        
        #print("payload_hex_len: ", payload_hex_len)
        
        buffer = hex2bin( payload_dict[self.dev_type]['prefix'] +
                          '00000000' +
                          '000000' +
                          payload_dict[self.dev_type][command]['hexByte'] +
                          '000000' + payload_hex_len ) 
        
        #print("buffer: prefix + seq + cmd + len:\n", bin2hex(buffer))
        
        buffer += cipher
        
        #print("buffer: prefix + seq + cmd + len + cipher:\n", bin2hex(buffer))
        
        crc = ubinascii.crc32(buffer)
        
        crc_hex = '%x' % crc #hex(crc)
        
        #print("hex crc32: ", crc_hex)
        
        buffer += hex2bin(crc_hex)
                       
        buffer += hex2bin(payload_dict[self.dev_type]['suffix'])
                                         
        print("Final buffer:\n", bin2hex(buffer))
                                                    
        return buffer



class GenericDevice(TuyaDevice):
    def __init__(self, dev_id, address, local_key=None, dev_type=None):
        super(GenericDevice, self).__init__(dev_id, address, local_key, dev_type)

    def status(self):
        print('status() entry')
        self.version = 3.3
        # open device, send request, then close connection
        payload = self.generate_payload('status')

        data = self._send_receive(payload)
        #print('\nstatus received data=', data)

        result = data[20:-8]  # hard coded offsets
        #print('\nresult=', result)
        #print('\nLength=', len(result))

        if result.startswith(b'{'):
            # this is the regular expected code path
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        elif self.version == 3.3:
            cipher = AESCipher(self.local_key)
            result = cipher.decrypt(result)
            
            print('\nResult=%r'% result)
            
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        else:
            print('Unexpected status() payload=%r', result)

        return result

    def set_status(self, on, switch=1):
        """
        Set status of the device to 'on' or 'off'.

        Args:
            on(bool):  True for 'on', False for 'off'.
            switch(int): The switch to set
        """
        # open device, send request, then close connection
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(SET, {switch:on})

        data = self._send_receive(payload)
        print('set_status received data=%r' % bin2hex(data))
        
        payload = data[20:-8]  # hard coded offsets
        
        print('set_status received data=%r' % bin2hex(payload))
        
        if payload.startswith(PROTOCOL_VERSION_BYTES_33):
            data = payload[len(PROTOCOL_33_HEADER) :]
            print('\n After removing 3.3=%r'% bin2hex(data))
        
        cipher = AESCipher(self.local_key)
        result = cipher.decrypt(data)
            
        print('\nResult=%r'% result)

        return data

    def turn_on(self, switch=1):
        """Turn the device on"""
        self.set_status(True, switch)

    def turn_off(self, switch=1):
        """Turn the device off"""
        self.set_status(False, switch)

    def set_timer(self, num_secs):
        """
        Set a timer.

        Args:
            num_secs(int): Number of seconds
        """
        # FIXME / TODO support schemas? Accept timer id number as parameter?
        # Dumb heuristic; Query status, pick last device id as that is probably the timer
        status = self.status()
        devices = status['dps']
        devices_numbers = list(devices.keys())
        devices_numbers.sort()
        dps_id = devices_numbers[-1]

        payload = self.generate_payload(SET, {dps_id:num_secs})

        data = self._send_receive(payload)
        #log.debug('set_timer received data=%r', data)
        print('set_timer received data=%r', data)
        return data


class OutletDevice(GenericDevice):
    def __init__(self, dev_id, address, local_key=None):
        dev_type = 'device'
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type)
