#   Import all modules and if not installed, install them
import os
import random
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import sys

try:
    import functions as utlities
    import httpx
    import phonenumbers
    import country_converter as coco
except:
    print("Install modules")
    os.system("pip install websocket-client")
    os.system("pip install phonenumbers")
    os.system("pip install country_converter")
    os.system("pip install httpx")
    os.system("pip install httpx[http2]")
    os.system("pip install requests")
    print("Good")
    import functions as utlities
    import httpx
    import phonenumbers
    import country_converter as coco

try:
    sys.argv[1]
    os._exit(1)
except:
    pass


#   Init base variables
tokensCreated = 0
tokensCreatedEmail = 0
tokensCreatedPhone = 0


#   Load proxies and username
try:
    proxies = [line.rstrip("\n") for line in open("data/proxies.txt")]
    if len(proxies) == 0:
        utlities.s_print("0 proxies on list")
        os._exit(1)
except:
    utlities.s_print("Can't open data/proxies.txt")
    os._exit(1)
try:
    usernames = (
        open("data/usernames.txt", encoding="cp437", errors="ignore")
        .read()
        .splitlines()
    )
except:
    utlities.s_print("Can't open data/usernames.txt")
    os._exit(1)
#   Load config.json
with open("config.json") as config_file:
    config = json.load(config_file)

#   Set user agent for generation process
userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"


def register(key, proxy):
    global tokensCreated
    global tokensCreatedEmail
    global tokensCreatedPhone

    try:
        #   Create httpx session for do all requests
        client = httpx.Client(
            http2=True, timeout=3, proxies={"all://": f"http://{proxy}"}
        )

        #   Get dcfduid and sdcfduid cookie
        response = client.get(
            "https://discord.com/register", headers={"user-agent": userAgent}
        )
        dcfduid = response.headers["Set-Cookie"].split("__dcfduid=")[1].split(";")[0]
        sdcfduid = response.headers["Set-Cookie"].split("__sdcfduid=")[1].split(";")[0]

        #   Init headers for the register request
        registerheaders = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "sec-ch-ua": '")Not=A?Brand";v="8", "Chromium";v="102", "Google Chrome";v="102"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "cookie": f"__dcfduid={dcfduid}; __sdcfduid={sdcfduid};",
            "origin": "https://discord.com",
            "referer": "https://discord.com/register",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-fingerprint": "964248117690130494.JnBuGSnGqwyZzjSLHElz3ME4JiQ",
            "user-agent": userAgent,
            "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMi4wLjUwMDIuMiBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTAyLjAuNTAwMi4yIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjEyMzg4NywiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=",
        }

        #   Get email
        result = utlities.getEmail()
        if result == False:
            return False
        methode = result.split(":")[len(result.split(":")) - 1]
        email = result.split(":")[0]
        if methode == "hotmailbox":
            passwordHotmail = result.split(":")[1]
        else:
            passwordHotmail = ""

        #   get password
        accpassword = utlities.random_char(10)
        #   Init params for register request
        payload = {
            "email": email,
            "password": accpassword,
            "date_of_birth": utlities.generateDOB(),
            "username": random.choice(usernames),
            "consent": True,
            "captcha_key": key,
            "gift_code_sku_id": None,
            "promotional_email_opt_in": False,
            "fingerprint": "964248117690130494.JnBuGSnGqwyZzjSLHElz3ME4JiQ",
        }
        if config["joinTokenOnCreation"]:
            payload["invite"] = config["serverInviteToJoinOnCreation"]

        #   Post the register request
        response = client.post(
            "https://discord.com/api/v9/auth/register",
            headers=registerheaders,
            json=payload,
        )

        #   Get token created
        try:
            token = response.json()["token"]
        except:
            utlities.s_print(f"[!] Bad hcaptcha")
            exit(1)

        #   Open a websocket with the token
        utlities.w2s(token, userAgent)
        time.sleep(1)

        #   Check if the token is not cloekd
        response = client.get(
            "https://discord.com/api/v9/users/@me/library",
            headers={
                "referer": "https://discord.com/channels/@me",
                "authorization": token,
            },
            timeout=20,
        )
        if response.status_code == 403:
            utlities.s_print(f"[-] Locked token generated: {token}")
            exit(1)
        utlities.s_print(f"[+] Unlocked token generated: {token}")

        #   Update gne title
        tokensCreated += 1
        os.system(
            "TITLE Tokens created : "
            + str(tokensCreated)
            + ", Tokens email verified : "
            + str(tokensCreatedEmail)
            + ", Tokens phone verified : "
            + str(tokensCreatedPhone)
        )

        #   Save token on tokens_unverified.txt file
        utlities.save(email, accpassword, token, "tokens_unverified.txt")

        if config["mailVerify"]:
            if (
                utlities.emailVerify(
                    email,
                    methode,
                    token,
                    dcfduid,
                    sdcfduid,
                    userAgent,
                    client,
                    passwordHotmail,
                )
                != True
            ):
                return False
            else:
                #   Update title
                tokensCreatedEmail += 1
                os.system(
                    "TITLE Tokens created : "
                    + str(tokensCreated)
                    + ", Tokens email verified : "
                    + str(tokensCreatedEmail)
                    + ", Tokens phone verified : "
                    + str(tokensCreatedPhone)
                )

                #   Save token
                utlities.save(email, accpassword, token, "tokens_mail_verified.txt")

        if config["use5sim"] or config["useSmsActivate"]:
            if (
                utlities.phoneVerify(
                    proxy, token, accpassword, dcfduid, sdcfduid, userAgent, client
                )
                != True
            ):
                return False
            else:
                #   Update title
                tokensCreatedPhone += 1
                os.system(
                    "TITLE Tokens created : "
                    + str(tokensCreated)
                    + ", Tokens email verified : "
                    + str(tokensCreatedEmail)
                    + ", Tokens phone verified : "
                    + str(tokensCreatedPhone)
                )

                #   Save token
                utlities.save(email, accpassword, token, "tokens_phone_verified.txt")

        if config["changeTokenPfp"]:
            utlities.changePfp(token, dcfduid, sdcfduid, userAgent, client)

    except Exception as e:
        utlities.s_print(f"Exited generation due to error : {e}")


def start():
    while True:
        try:
            #   Get a proxy and format it
            proxy =  random.choice(proxies)
            if (":" in proxy )== False:
                utlities.s_print(f"Bad proxies on list : {proxy}")
                continue
            proxyraw = proxy
            proxyFormated = utlities.get_formatted_proxy(proxyraw)
            #   get a captcha key returned by the solver server
            key = utlities.getCaptchaKey(proxyFormated,   "https://discord.com/register" , "4c672d35-0701-42b2-88c3-78380b0db560")
            if key != False:
                #   Start generation with captcha key returned before
                #register(key,proxyFormated)
                threading.Thread(target=register, args=(key.replace("\n",""), proxyFormated)).start()

        except Exception as e:
            print(e)
            continue

def mainhandler():
    try:
        threads = int(input("Threads: "))
    except:
        utlities.s_print("Need to enter a valid number")
        exit(1)

    with ThreadPoolExecutor(max_workers=threads) as exe:
        for x in range(threads):
            exe.submit(start)
if __name__ == '__main__':
    mainhandler()