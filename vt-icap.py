#!/bin/env python
# -*- coding: utf8 -*-

import SocketServer
import zlib
import json
import time
import hashlib
import urllib
import urllib2
import requests

# python-magic
import magic

from pyicap import *

class ThreadingSimpleServer(SocketServer.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    # Feel free to tinker with these variables
    vt_apikey = ""
    vt_threshold = 5
    mime_types = ['application/x-dosexec', 'application/octet-stream', 'application/pdf']

    def get_vt_result(self, sha256):
        parameters = {"resource": sha256, "apikey": self.vt_apikey}
        vtdata = urllib.urlencode(parameters)
        req = urllib2.Request('https://www.virustotal.com/vtapi/v2/file/report', vtdata)
        response = urllib2.urlopen(req)
        return json.loads(response.read())

    def check_file(self, data, uri):
        mime_type = magic.from_buffer(data, mime=True)
        if mime_type == 'application/gzip': #peek inside compressed content
            data = zlib.decompress(data, 16+zlib.MAX_WBITS)
            mime_type = magic.from_buffer(data, mime=True)
        if mime_type in self.mime_types:
            sha256 = hashlib.sha256(data).hexdigest()
            print "Checking %s from %s" %(sha256, uri)
            result = self.get_vt_result(sha256)
            if result['response_code'] == 1 and result['positives'] >= self.vt_threshold: #in VT and we care about it
                return False
            if result['response_code'] == 0: #not in VT
                files = {"file": (sha256, data), "apikey" : self.vt_apikey}
                requests.post("https://www.virustotal.com/vtapi/v2/file/scan", files=files)
                max_count = 6 # We'll wait 3 minutes and then fail open
                count = 0
                while count < max_count:
                    result = self.get_vt_result(sha256)
                    if result['response_code'] == 1 and result['positives'] >= self.vt_threshold: #in VT and we care about it
                        return False
                    if result['response_code'] == 1 and result['positives'] < self.vt_threshold: #in VT and we don't care about it
                        return True
                    time.sleep(30)
                    count += 1
        return True 

    def vt_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'RESPMOD')
        self.set_icap_header('Service', 'VT ICAP Scanner 1.0')
        self.set_icap_header('Preview', '4096')
        self.set_icap_header('Transfer-Preview', '*')
        self.set_icap_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header('Transfer-Complete', '')
        self.set_icap_header('Max-Connections', '100')
        self.set_icap_header('Options-TTL', '3600')
        self.send_headers(False)

    def vt_RESPMOD(self):
        self.set_enc_status(' '.join(self.enc_res_status))
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        # The code below is only copying some data.
        # Very convoluted for such a simple task.
        # This thing needs a serious redesign.
        # Well, without preview, it'd be quite simple...
        payload = ''
        chunk = ''
        if not self.has_body:
            self.send_headers(False)
            return
        if self.preview:
            while True:
                chunk = self.read_chunk()
                if chunk == '':
                    break
                payload += chunk
            if self.ieof:
                if len(payload) > 0:
                    if self.check_file(payload, self.enc_req[1]):
                        self.set_icap_response(200)
                        self.send_headers(True)
                        self.write_chunk(payload)
                        self.write_chunk('')
                    else:
                        self.send_error(403, "Malicious Download Found")
                else:
                    self.send_headers(False)
                return
            self.cont()
            while True:
                chunk = self.read_chunk()
                if chunk == '':
                    break
                else:
                    payload += chunk
            if len(payload) > 0:
                if self.check_file(payload, self.enc_req[1]):
                    self.set_icap_response(200)
                    self.send_headers(True)
                    self.write_chunk(payload)
                    self.write_chunk('')
                else:
                    self.send_error(403, "Malicious Download Found")
            else:
                self.send_headers(False)
        else:
            payload = ''
            while True:
                chunk = self.read_chunk()
                if chunk == '':
                    break
                payload += chunk
            if len(payload) > 0:
                if self.check_file(payload, self.enc_req[1]):
                    self.set_icap_response(200)
                    self.send_headers(True)
                    self.write_chunk(payload)
                    self.write_chunk('')
                else:
                    self.send_error(403, "Malicious Download Found")
            else:
                self.send_headers(False)

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"
