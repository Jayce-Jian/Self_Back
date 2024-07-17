#! /usr/bin/env python3
# -*- coding: UTF-8 -*-

import sys
import json
import urllib.request
import urllib.parse
import http.client
from Secrets import SECRETS

headers={"Content-Type":"application/json",
        "Trackingmore-Api-Key":SECRETS['trackingmore']['token'],
        'X-Requested-With':'XMLHttpRequest'
        }
class track:

    def trackingmore(requestData, urlStr, method):

        if method == "get":

            url = 'http://api.trackingmore.com/v2/trackings/get'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl, headers=headers)
            result = urllib.request.urlopen(req).read()

        elif method == "post":

            url = 'http://api.trackingmore.com/v2/trackings/post'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "batch":

            url = 'http://api.trackingmore.com/v2/trackings/batch'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "codeNumberGet":

            url = 'http://api.trackingmore.com/v2/trackings'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="GET")
            result = urllib.request.urlopen(req).read()

        elif method == "codeNumberPut":

            url = 'http://api.trackingmore.com/v2/trackings'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="PUT")
            result = urllib.request.urlopen(req).read()

        elif method == "codeNumberDelete":

            url = 'http://api.trackingmore.com/v2/trackings'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="DELETE")
            result = urllib.request.urlopen(req).read()

        elif method == "realtime":

            url = 'http://api.trackingmore.com/v2/trackings/realtime'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "carriers":

            url = 'http://api.trackingmore.com/v2/carriers'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="GET")
            result = urllib.request.urlopen(req).read()

        elif method == "carriers/detect":

            url = 'http://api.trackingmore.com/v2/carriers/detect'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="GET")
            result = urllib.request.urlopen(req).read()

        elif method == "update":

            url = 'http://api.trackingmore.com/v2/trackings/update'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "getuserinfo":

            url = 'http://api.trackingmore.com/v2/trackings/getuserinfo'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="GET")
            result = urllib.request.urlopen(req).read()

        elif method == "getstatusnumber":

            url = 'http://api.trackingmore.com/v2/trackings/getstatusnumber'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="GET")
            result = urllib.request.urlopen(req).read()

        elif method == "notupdate":

            url = 'http://api.trackingmore.com/v2/trackings/notupdate'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "remote":

            url = 'http://api.trackingmore.com/v2/trackings/remote'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "costtime":

            url = 'http://api.trackingmore.com/v2/trackings/costtime'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "delete":

            url = 'http://api.trackingmore.com/v2/trackings/delete'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        elif method == "updatemore":

            url = 'http://api.trackingmore.com/v2/trackings/updatemore'
            RelUrl = url + urlStr
            req = urllib.request.Request(RelUrl,requestData.encode('utf-8'), headers=headers,method="POST")
            result = urllib.request.urlopen(req).read()

        return result




