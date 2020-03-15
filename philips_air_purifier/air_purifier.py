import json
from base64 import b64decode, b64encode

import requests
from pyaes import AESModeOfOperationCBC, Decrypter, Encrypter

from .key_exchange import KeyExchange

PHILIPS_API_ENDPOINTS = {
    'firmware': 'http://{}/di/v1/products/0/firmware',
    'security': 'http://{}/di/v1/products/0/security',
    'userinfo': 'http://{}/di/v1/products/0/userinfo',
    'wifi': 'http://{}/di/v1/products/0/wifi',
    'air': 'http://{}/di/v1/products/1/air',
    'device': 'http://{}/di/v1/products/1/device',
    'filter': 'http://{}/di/v1/products/1/fltsts'
}

PHILIPS_ERROR_CODES = {
    32768: 'Water tank is removed',
    49408: 'Water refill alert',
    49411: 'Pre-filter and wick cleaning alert'
}

MAPPER = [
    (('pwr', 'air', 'power'), ['0', 'off', '1', 'on']),
    (('pm25', 'air', 'pm_2_5'), []),
    (('rh', 'air', 'humidity'), []),
    (('rhset', 'air', 'target_humidity'), []),
    (('iaql', 'air', 'allergen_index'), []),
    (('temp', 'air', 'temperature'), []),
    (('func', 'air', 'function'), ['P', 'purification', 'PH', 'purification_and_humidification']),
    (('mode', 'air', 'mode'), ['P', 'auto', 'A', 'allergen', 'S', 'sleep', 'M', 'manual', 'B', 'bacteria', 'N', 'night']),
    (('om', 'air', 'fan_speed'), ['s', 'silent', 't', 'turbo']),
    (('aqil', 'air', 'brightness'), []),
    (('uil', 'air', 'ui_light'), ['0', 'off', '1', 'on']),
    (('ddp', 'air', 'ui_index'), ['0', 'allergen_index', '1', 'pm_2_5']),
    (('wl', 'air', 'water_level'), []),
    (('cl', 'air', 'child_lock'), []),
    (('dt', 'air', 'timer_hours'), []),
    (('dtrs', 'air', 'timer_minutes'), []),
    (('wicksts', 'filter', 'wick_filter_life'), []),
    (('fltsts0', 'filter', 'pre_filter_life'), []),
    (('fltsts1', 'filter', 'hepa_filter_life'), []),
    (('fltsts2', 'filter', 'carbon_filter_life'), []),
]

class AirPurifier:
    def __init__(self, ip):
        self.api_endpoints = {x: PHILIPS_API_ENDPOINTS[x].format(ip) for x in PHILIPS_API_ENDPOINTS}
        self._mapf = {}
        self._mapr = {}
        for m in MAPPER:
            _mapf = {'endpoint': m[0][1], 'key': m[0][0], 'mapf': {}, 'mapr': {}}
            _mapr = {'name': m[0][2], 'mapf': {}, 'mapr': {}}
            for a, b in zip(m[1][::2], m[1][1::2]):
                _mapf['mapr'][a] = b
                _mapf['mapf'][b] = a
                _mapr['mapr'][a] = b
                _mapr['mapf'][b] = a
            self._mapf[m[0][2]] = _mapf
            self._mapr[m[0][0]] = _mapr
        self._set_session_key()

    def _api_put(self, endpoint, obj, encrypt=True, retry=True):
        data = self._encrypt(obj) if encrypt else json.dumps(obj)
        r = requests.put(self.api_endpoints[endpoint], data=data)
        if r.status_code == 400 and retry:
            self._set_session_key()
            return self._api_put(endpoint, obj, encrypt, retry=False)

        r.raise_for_status()
        return r.text if encrypt else r.json()

    def _api_get(self, endpoint, field=None, decrypt=True, retry=True):
        r = requests.get(self.api_endpoints[endpoint])
        r.raise_for_status()
        if not decrypt:
            return r.text

        try:
            obj = self._decrypt(r.text)
            if field:
                return obj.get(field)
            else:
                return obj
        except Exception as e:
            if retry:
                self._set_session_key()
                return self._api_get(endpoint, field, decrypt, retry=False)
            else:
                raise e

    def _set_session_key(self):
        kex = KeyExchange()
        resp = self._api_put('security', {'diffie': kex.get_public_key()}, False)
        tmp_key = kex.get_exchanged_key(resp['hellman'])
        dec = Decrypter(AESModeOfOperationCBC(tmp_key))
        self.session_key = dec.feed(bytes.fromhex(resp['key']))
        self.session_key += dec.feed()

    def _decrypt(self, encrypted_message):
        dec = Decrypter(AESModeOfOperationCBC(self.session_key))
        message = dec.feed(b64decode(encrypted_message))
        message += dec.feed()
        return json.loads(message[2:].decode())

    def _encrypt(self, data):
        enc = Encrypter(AESModeOfOperationCBC(self.session_key))
        message = '\n\n' + json.dumps(data)
        enc_message = enc.feed(message)
        enc_message += enc.feed()
        return b64encode(enc_message)

    def get(self, field):
        if field in self._mapf:
            m = self._mapf[field]
            value = self._api_get(m['endpoint'], m['key'])
            return m['mapr'][value] if value in m['mapr'] else value
        else:
            obj = self._api_get(field)
            ret = {}
            for k, v in obj.items():
                if k in self._mapr:
                    _mapr = self._mapr[k]
                    k = _mapr['name']
                    if v in _mapr['mapr']:
                        v = _mapr['mapr'][v]

                ret[k] = v
            return ret

    def set(self, field, value):
        m = self._mapf[field]
        if value in m['mapf']:
            value = m['mapf'][value]
        self._api_put(m['endpoint'], {m['key']: value})
        # for chaining
        return self

    def ensure(self, field, value):
        current = self.get(field)
        return self if value == current else self.set(field, value)

    def is_powered_on(self):
        return self._api_get('air', 'pwr') == '1'

    def is_locked(self):
        return self._api_get('air', 'cl')

    def is_humidifier_enabled(self):
        return 'H' in self._api_get('air', 'func')

    def is_display_on(self):
        return self._api_get('air', 'uil') == '1'

    def get_temperature(self):
        return self._api_get('air', 'temp')

    def get_humidity(self):
        return self._api_get('air', 'rh')

    def get_desired_humidity(self):
        return self._api_get('air', 'rhset')

    def get_pm25_level(self):
        return self._api_get('air', 'pm25')

    def get_allergen_index(self):
        return self._api_get('air', 'iaql')

    def get_brightness(self):
        return self._api_get('air', 'aqil')

    def get_error_code(self):
        return self._api_get('air', 'err')

    def get_water_level(self):
        return self._api_get('air', 'wl')

    def get_fan_speed(self):
        return self._api_get('air', 'om')

    def get_mode(self):
        return self._api_get('air', 'mode')

    def get_timer(self):
        return self._api_get('air', 'dtrs') / 60.0

    def get_display_mode(self):
        return self._api_get('air', 'ddp')

    def power_on(self):
        if not self.is_powered_on():
            self._api_put('air', {'pwr': '1'})

    def power_off(self):
        if self.is_powered_on():
            self._api_put('air', {'pwr': '0'})

    def turn_display_on(self):
        if not self.is_display_on():
            self._api_put('air', {'uil': '1'})

    def turn_display_off(self):
        if self.is_display_on():
            self._api_put('air', {'uil': '0'})

    def lock(self):
        if not self.is_locked():
            self._api_put('air', {'cl': True})

    def unlock(self):
        if self.is_locked():
            self._api_put('air', {'cl': False})

    def enable_humidifier(self):
        if not self.is_humidifier_enabled():
            self._api_put('air', {'func': 'PH'})

    def disable_humidifier(self):
        if self.is_humidifier_enabled():
            self._api_put('air', {'func': 'P'})

    def set_desired_humidity(self, humidity):
        if humidity != self.get_desired_humidity():
            self._api_put('air', {'rhset': humidity})

    def set_brightness(self, brightness):
        if brightness != self.get_brightness():
            self._api_put('air', {'aqil': brightness})

    def set_fan_speed(self, fan_speed):
        if fan_speed != self.get_fan_speed():
            self._api_put('air', {'om': fan_speed})

    def set_mode(self, mode):
        if mode != self.get_mode():
            self._api_put('air', {'mode': mode})

    def set_timer(self, time):
        self._api_put('air', {'dt': time})

    def set_display_mode(self, mode):
        if mode != self.get_display_mode():
            self._api_put('air', {'ddp': mode})
