from smartoutlet import OutletDevice

# Your wi-fi settings
ssid_ = ""
wp2_pass = ""

# Your smart power outlet device settings
DEVICE_ID_HERE = ""
IP_ADDRESS = ""
LOCAL_KEY = ""

# connecting to wi-fi
def do_connect():
    import network
    sta_if = network.WLAN(network.STA_IF)
    if not sta_if.isconnected():
        print('connecting to network...')
        sta_if.active(True)
        sta_if.connect(ssid_, wp2_pass)
        while not sta_if.isconnected():
            pass
    print('network config:', sta_if.ifconfig())
do_connect()

# connecting to the power outlet
outlet = OutletDevice(DEVICE_ID_HERE, IP_ADDRESS, LOCAL_KEY)

#Turn off the plug
outlet.turn_off()

status = outlet.status()

if 'dps' in status:
    if status['dps']['1'] == True:
        print("Plug is ON")
    else:
        print("Plug is OFF")
    
#Turn on the plug
outlet.turn_on()
