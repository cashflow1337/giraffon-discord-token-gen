#   import all modules
import os
import random
import string
import websocket
import json
from threading import RLock, Thread
import time
import requests
import phonenumbers 
import country_converter as coco
import base64

#   For print with many thread at same time
class SynchronizedEcho(object):
    print_lock = RLock()

    def __init__(self, global_lock=True):
        if not global_lock:
            self.print_lock = RLock()

    def __call__(self, msg):
        with self.print_lock:
            print(msg)
s_print = SynchronizedEcho()

#   Load config.json
with open('config.json') as config_file:
    config = json.load(config_file)




#   Return random string of length y
def random_char(y):
    return ''.join(random.choice(string.ascii_letters) for x in range(y))

#   Save token on file
def save(email,pas,token,path):
    f = open(path , "a+")
    f.write(f"{email}:{pas}:{token}")
    f.write("\n")
    f.close()

#   Format proxies for can be use with httpx and solver
def get_formatted_proxy(proxy):
    if '@' in proxy:
        return proxy
    elif len(proxy.split(':')) == 2:
        return proxy
    else:
        if '.' in proxy.split(':')[0]:
            return ':'.join(proxy.split(':')[2:]) + '@' + ':'.join(proxy.split(':')[:2])
        else:
            return ':'.join(proxy.split(':')[:2]) + '@' + ':'.join(proxy.split(':')[2:])

#   Generate bron date
def generateDOB():
    year = str(random.randint(1997,2001))
    month = str(random.randint(1, 12))
    day = str(random.randint(1,28))
    if len(month) == 1:
        month = '0' + month
    if len(day) == 1:
        day = '0' + day
    return year + '-' + month + '-' + day

def getCaptchaKey(proxy,siteUrl,siteKey,canBeSolveInOneClick=False):
    js = {
        "proxy": proxy,
        "siteUrl" : siteUrl,
        "siteKey":siteKey,
    }
    if canBeSolveInOneClick : 
        js["canBeSolveInOneClick"] = "true"
    try:
        session = requests.Session()
        session.trust_env = False
        response = session.post(f"http://"+config["sovlerIp"]+"/generateKey", json=js)
    except:
        s_print(bad("Can't get access to the solver url, retry"))
        return False
    key = response.text
    if "P0_" in key:
        s_print("[+] Solved hcaptcha")
        return key
    else:
        return False

#   Open web socket with token
def w2s(token,userAgent):
    v = {
        "op": 2,
        "d": {
            "token": token,
            "capabilities": 253,
            "properties": {
                "os": "Windows",
                "browser": "Chrome",
                "device": "",
                "system_locale": "en-US",
                "browser_user_agent": userAgent,
                "browser_version": "99.0.4844.51",
                "os_version": "10",
                "referrer": "",
                "referring_domain": "",
                "referrer_current": "",
                "referring_domain_current": "",
                "release_channel": "stable",
                "client_build_number": 114764,
                "client_event_source": ""
            },
            "presence": {
                "status": "online",
                "since": 0,
                "activities": [],
                "afk": False
            },
            "compress": False,
            "client_state": {
                "guild_hashes": {},
                "highest_last_message_id": "0",
                "read_state_version": 0,
                "user_guild_settings_version": -1,
                "user_settings_version": -1
            }
        }
    }
    ws = websocket.WebSocket()
    ws.connect('wss://gateway.discord.gg/?v=6&encoding=json')
    response = ws.recv()
    event = json.loads(response)
    f = json.dumps(v)
    ws.send(f)
    ws.close()


#   get email for register account
def getEmail():
    methode =""
    if config["useHotmailbox"]:
        
        #   Buy new email
        response = requests.get('https://api.hotmailbox.me/mail/buy?apikey='+config['hotmailboxApiKey']+'&mailcode=HOTMAIL&quantity=1')
        try:
            email = response.json()["Data"]["Emails"][0]["Email"]
            passwordHotmail =  response.json()["Data"]["Emails"][0]["Password"]
        except:
            s_print("Can't get an email, hotmailbox return : "+response.json()["Message"])
            return False
        
        if config["saveBuyHotmails"] :
            #   Save email on file
            try:
                open( config["saveBuyHotmailsPath"],"a").write(email+":"+passwordHotmail+"\n")
            except:
                s_print("Can't save the save email on "+config["saveBuyHotmailsPath"]+", pass")

        methode = "hotmailbox"

    else:
        #   Generate random email who finish with the custom domain put on config
        email = random_char(20)+ config["customDomain"] 
        methode = "custom"
    
    
    if methode == "hotmailbox":
        return email+":"+passwordHotmail+":"+methode
    else:
        return email+":"+methode




#   Verify token by email
def emailVerify(email,methode,token,dcfduid,sdcfduid,userAgent,client,passwordHotmail=""):

    verifyheaders = {
        'origin': 'https://discord.com',
        'referer': 'https://discord.com/verify',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'sec-ch-ua-mobile': '?0',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': userAgent,
        'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzk5LjAuNDg0NC41MSBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiOTkuMC40ODQ0LjUxIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjExNDc2NCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=',
        'Cookie': f'__dcfduid={dcfduid}; __sdcfduid={sdcfduid}'
    }

    if methode == "hotmailbox":

        #   Get verification email
        response = requests.get("https://getcode.hotmailbox.me/discord?email="+email+"&password="+passwordHotmail+"&timeout="+str(config["hotmailBoxTimeout"])   )
        try:
            link = response.json()["VerificationCode"].replace("\\r","").replace("\\n","").replace("\r","").replace("\n","")
        except:
            s_print("Can't get validation link, hotmailbox return : "+response.json()["Message"])
            return False

        #   Get the verification token
        response=  client.get(link)

        try:
            verifypayload = {
                'token': response.headers["location"].split("#token=")[1]
            }
        except:
            s_print("Hotmailbox return wrong link, verify all code")
            return False

        #   Verify token with mail with url redirected with the before request
        client.post("https://discord.com/api/v9/auth/verify", headers=verifyheaders, json=verifypayload)

        #   Token successful email verifoed
        s_print("Email Verified "+token)
        return True

    else:
        while True:
            
            #   Send request to email server
            try:
                verifytoken = requests.get("http://"+config["emailServerIp"]+"/getToken="+email.lower())
            except:
                time.sleep(1)
                continue

            if verifytoken.text != "There are currently no active Emails on this account.":

                #   get the verify code after upn=
                verifytoken = verifytoken.text


                #   Get the verification token
                response=  client.get("https://click.discord.com/ls/click?upn="+verifytoken)

                try:
                    verifypayload = {
                        'token': response.headers["location"].split("#token=")[1]
                    }
                except:
                    s_print("Email server return wrong link, verify all config")
                    return False

                #   Verify token with mail with url redirected with the before request
                client.post("https://discord.com/api/v9/auth/verify", headers=verifyheaders, json=verifypayload)

                #   Token successful email verifoed
                s_print("Email Verified "+token)
                return True
            else:
                time.sleep(1)
                continue
                


#   Verify token by phone
def phoneVerify(proxy,token,password,dcfduid,sdcfduid,userAgent,client):
    if config["use5sim"]:
        #   Get phone number with 5sim
        response = requests.get("https://5sim.net/v1/user/buy/activation/"+config["5simContry"]+"/"+config["5simOperator"]+"/discord",headers={"Authorization":"Bearer "+config["5simApiKey"]  })
        if response.status_code == 400 :
            s_print("No balance on phone api key")
            return False
        elif response.status_code == 401 :
            s_print("Invalid phone api key")
            return False
        elif response.status_code == 404:
            s_print("5sim return an error 404. Is the country, operator and product key valid ?")
            return False
        try:
            if  "+" in response.json()["phone"] :
                phone_id = str(response.json()["id"])
                phone_number = response.json()["phone"]
                try :
                    phone_contry = coco.convert(names=phonenumbers.region_code_for_country_code(phonenumbers.parse(phone_number, None).country_code), to="name") 
                except:
                    s_print("Can't parse the phone number : "+phone_number)
                s_print("One phone number created -> phone id : "+phone_id+", phone number : "+phone_number+", phone contry -> "+phone_contry)
            
            else:
                s_print("5sim return "+response.text)
                return False
        except:
            s_print("5sim return "+response.text)
            return False
    else:
        #   Get phone number with sms-activate
        response = requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=getNumber&service=ds&country="+config["smsActivateContry"])
        if( "ACCESS_NUMBER" in response.text) ==False:
            s_print("Can't get a phone number, server rerurn : "+response.text)
            return False
        phone_id = response.text.split(":")[1]
        phone_number ="+"+ response.text.split(":")[2]
        try:
            phone_contry = coco.convert(names=phonenumbers.region_code_for_country_code(phonenumbers.parse(phone_number, None).country_code), to="name") 
        except:
            s_print("Can't parse the phone number : "+phone_number)
            requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=setStatus&status=8&id="+phone_id)
        s_print("One phone number created -> phone id : "+phone_id+", phone number : "+phone_number+", phone contry -> "+phone_contry)


    #   get captcha key
    while True:
        captchaKey = getCaptchaKey(proxy,   "https://discord.com/channels/@me" , "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34",True)
        if captchaKey != False:
            break
        else:
            continue


    #   Init playload and headers for the futur requests
    payload = {
        'change_phone_reason': 'user_settings_update',
        'phone': phone_number,
        "captcha_key": captchaKey
    }
    changeSettingsHeaders = {
        'origin': 'https://discord.com',
        'referer': 'https://discord.com/channels/@me',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'sec-ch-ua-mobile': '?0',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': userAgent,
        'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzk5LjAuNDg0NC41MSBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiOTkuMC40ODQ0LjUxIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjExNDc2NCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=',
        'Cookie': f'__dcfduid={dcfduid}; __sdcfduid={sdcfduid}',
        "authorization" : token
    }

    #   Send phone number to discord
    try:
        response = client.post('https://discord.com/api/v9/users/@me/phone', json=payload, headers=changeSettingsHeaders, timeout=8)
    except:
        s_print("Can't post the add phone number request"  )
        if config["use5sim"]:
            requests.get('https://5sim.net/v1/user/cancel/' + phone_id, headers={"Authorization":"Bearer "+config["5simApiKey"],"Accept":'application/json' } );  
        else:
            requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=setStatus&status=8&id="+phone_id)
        return False

    #   Check if number is valid
    if 'Invalid phone number' in response.text or 'Please use a valid mobile phone number' in response.text:
        s_print("The number "+phone_number+" is invalid"  )
        if config["use5sim"]:
            requests.get('https://5sim.net/v1/user/cancel/' + phone_id, headers={"Authorization":"Bearer "+config["5simApiKey"],"Accept":'application/json' } );  
        else:
            requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=setStatus&status=8&id="+phone_id)
        return False


    if config["use5sim"]:
        #   Get verification code with 5sim
        for i in range(120):
            response = requests.get( "https://5sim.net/v1/user/check/"+phone_id, headers = {'Authorization': "Bearer "+config["5simApiKey"]})
            try:
                if  len(response.json()["sms"][0]["code"])  >0 :
                    sms_code =  str(response.json()["sms"][0]["code"])
                    s_print("One sms received : "+sms_code)
                    requests.get(  "https://5sim.net/v1/user/finish/"+phone_id, headers={'Authorization': 'Bearer '+config["5simApiKey"]} )
                    break
            except:
                pass
            time.sleep(1)
        if i == 59 :
            s_print("No sms received for "+phone_number)
            requests.get('https://5sim.net/v1/user/cancel/' + phone_id, headers={"Authorization":"Bearer "+config["5simApiKey"],"Accept":'application/json' } );  
            return False
    else:
        #   Get verification code with sms-activate
        for i in range(120):
            response = requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=getStatus&id="+phone_id)
            if response.text.split(":")[0] == "STATUS_OK":
                sms_code = response.text.split(":")[1]
                s_print("One sms received : "+sms_code)
                break
            
            time.sleep(1)
        
        if i==59 :
            s_print("No sms received for "+phone_number)
            requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=setStatus&status=8&id="+phone_id)
            return False
        

    return submit_sms(  token,password,phone_number,phone_id,sms_code, changeSettingsHeaders,client)           

#   Verify phone of a token
def submit_sms(token,password,phone_number,phone_id,sms_code, changeSettingsHeaders,client ) :
    
    #   Get verification code
    try:
        response = client.post('https://discord.com/api/v9/phone-verifications/verify', json={
            'code': str(sms_code),
            'phone': phone_number
        }, headers=changeSettingsHeaders, timeout=8)
    except:
        s_print("Can't post the first request for verify phone")
        if config["use5sim"]:
            requests.get('https://5sim.net/v1/user/cancel/' + phone_id, headers={"Authorization":"Bearer "+config["5simApiKey"],"Accept":'application/json' } );  
        else:
            requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=setStatus&status=8&id="+phone_id)
        return False

    #   Get sms verification token
    try:
        sms_token = response.json()['token']
    except:
        s_print("Can't verify number, discord return "+ response.json()['message']  )

    #   verify by phone with the verification token
    try:
        response = client.post('https://discord.com/api/v9/users/@me/phone', json={
            'change_phone_reason': "user_settings_update",
            'password': password,
            'phone_token': sms_token
        }, headers=changeSettingsHeaders, timeout=8)
    except:
        s_print("Can't post the second request for verify phone")
        if config["use5sim"]:
            requests.get('https://5sim.net/v1/user/cancel/' + phone_id, headers={"Authorization":"Bearer "+config["5simApiKey"],"Accept":'application/json' } );  
        else:
            requests.get("https://sms-activate.org/stubs/handler_api.php?api_key="+config["smsActivateApiKey"]+"&action=setStatus&status=8&id="+phone_id)
        return False

    s_print("Token "+token+" has been phone verified successful")

    return True


#   Load image and encode as base64
def getRandomPicture():
    files = os.listdir('data/pfps')
    with open('data/pfps' + "/" + files[random.randrange(0, len(files))], "rb") as pic:
        return "data:image/png;base64,"+base64.b64encode(pic.read()).decode('utf-8')

#   Function for change pfp of a discord token
def changePfp(token,dcfduid,sdcfduid,userAgent,client):
    playload = {
            "avatar": getRandomPicture()
        }
    avatarheader = {
        'authorization': token,
        'Content-Type': 'application/json',
        'origin': 'https://discord.com',
        'referer': 'https://discord.com/channels/@me',
        'user-agent': userAgent,
        'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzk5LjAuNDg0NC41MSBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiOTkuMC40ODQ0LjUxIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjExNDc2NCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=',
        'Cookie': f'__dcfduid={dcfduid}; __sdcfduid={sdcfduid};'
    }
    client.patch("https://discord.com/api/v9/users/@me", headers=avatarheader, json=playload)