# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from os import environ
import logging
import requests
import json
import random
# from Crypto.Hash import keccak


import datetime
import traceback
from eth_abi.abi import encode
from eth_abi_ext import decode_packed

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = "http://localhost:8080/host-runner"
network = "localhost"

logger.info(f"HTTP rollup_server url is {rollup_server}")
logger.info(f"Network is {network}")

# Function selector to be called during the execution of a voucher that transfers funds,
# which corresponds to the first 4 bytes of the Keccak256-encoded result of "transfer(address,uint256)"
TRANSFER_FUNCTION_SELECTOR = b'\xa9\x05\x9c\xbb'

# Function selector to be called during the execution of a voucher that transfers funds,
# which corresponds to the first 4 bytes of the Keccak256-encoded result of "withdrawEther(address,uint256)"
WITHDRAW_FUNCTION_SELECTOR = b'R/h\x15'

# Setup contracts addresses
ETHERPortalFile = open(f'./EtherPortal.json')
etherPortal = json.load(ETHERPortalFile)


logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = "http://localhost:8080/host-runner"

# k = keccak.new(digest_bits=256)
# k.update(b'announce_winner(address,address,address)')
# ANNOUNCE_WINNER_FUNCTION = k.digest()[:4] # first 4 bytes

logger.info(f"HTTP rollup_server url is {rollup_server}")

BALANCES = {}
VOUCHERS = {}
CARS_USER = []
CARDLIST = [
    { 'id': 1, 'title': 'Drift King', 'strength': '2.5', 'speed': '22.5', 'rarity': 'legendary', 'chance': [1,10], 'image': 'image_7', 'win_chance': 75 },
    { 'id': 2, 'title': 'Ferrari', 'strength': '20', 'speed': '5', 'rarity': 'legendary', 'chance': [11,20], 'image': 'image_8', 'win_chance': 75 },
    { 'id': 3, 'title': 'Hudson', 'strength': '15', 'speed': '10', 'rarity': 'legendary', 'chance': [21,30], 'image': 'image_3', 'win_chance': 75 },
    { 'id': 4, 'title': 'Red Bullet', 'strength': '10', 'speed': '10', 'rarity': 'rare', 'chance': [31,101], 'image': 'image_1', 'win_chance': 30 },
    { 'id': 5, 'title': 'Yellow Flash', 'strength': '10', 'speed': '10', 'rarity': 'rare', 'chance': [101,171], 'image': 'image_5', 'win_chance': 30 },
    { 'id': 6, 'title': 'Monster Truck', 'strength': '10', 'speed': '10', 'rarity': 'rare', 'chance': [172, 241], 'image': 'image_6', 'win_chance': 30 },
    { 'id': 7, 'title': 'Fusca', 'strength': '7.5', 'speed': '7.5', 'rarity': 'common', 'chance': [242,541], 'image': 'image_4', 'win_chance': 15 },
    { 'id': 8, 'title': 'Chevette', 'strength': '10', 'speed': '5', 'rarity': 'common', 'chance': [542,841], 'image': 'image_2', 'win_chance': 15 },
    { 'id': 9, 'title': 'Kombi', 'strength': '5', 'speed': '10', 'rarity': 'common', 'chance': [842, 1141], 'image': 'image_9', 'win_chance': 15 },
]
RUNS = []


def post(endpoint, json):
    response = requests.post(f"{rollup_server}/{endpoint}", json=json)
    logger.info(f"Received {endpoint} status {response.status_code} body {response.content}")


def tryLuck(seed, min, max):
    random.seed(seed)
    return random.randint(min, max)

def generateVoucher(payload):
    user_id = payload["user_id"]
    amount = float(payload["balance"]) / 10 ** 18
    address = payload["address"]
    if user_id not in BALANCES:
        BALANCES[user_id] = 0
    BALANCES[user_id] -= float(payload["balance"])
    if user_id not in VOUCHERS:
            VOUCHERS[user_id] = 0
    VOUCHERS[user_id] += amount
    
    # Generate the payload for the voucher
    withdraw_payload = WITHDRAW_FUNCTION_SELECTOR + encode(['address', 'uint256'], [address, int(amount)])
    voucher = {"destination": rollup_address, "payload": "0x" + withdraw_payload.hex()}
    requests.post(rollup_server + "/voucher", json=voucher)
    
    return "accept"

def openBox(payload):

    rand_num = tryLuck(payload["seed"], 1, 1141)
    user_id = payload["user_id"]
    amount = payload["box_value"]
    created_at = payload["created_at"]
    selected_car = None
    if BALANCES[user_id] < amount:
         return "reject"
    BALANCES[user_id] -= amount

    for car in CARDLIST:
        min_chance, max_chance = car['chance']
        if min_chance <= rand_num <= max_chance:
            selected_car = car
            break  # Break the loop when a car is selected

    CARS_USER.append({
        'user_id': user_id,
        'car': selected_car,
        'created_at': created_at,
    })

    return "accept"
     
def calculateScore(car):
        return float(car['strength']) + float(car['speed'])
       
def announceWinner(payload):
    car_id_1 = payload["car_id_1"]
    car_1 = CARDLIST[car_id_1 - 1]
    car_2 = CARDLIST[5]
    user_id_1 = payload["user_id_1"]
    discount = 1 * 10 ** 17
    price = 2 * 10 ** 17
    if BALANCES[user_id_1] < discount:
        return "reject"
    BALANCES[user_id_1] -= discount
    user_id_2 = "0x0000000-bot"
    run_id = len(RUNS) + 1
    winner = None
    seed = payload["seed"]
    luck_num = tryLuck(seed, 1, 100)
        
    if luck_num < car_1['win_chance']:
        winner = user_id_1
    else:
        winner = user_id_2

    if winner == user_id_1:
        BALANCES[winner] += price
            
                
    RUNS.append({
        'run_id': run_id,
        'car_1': car_1,
        'car_2': car_2,
        'user_id_1': user_id_1,
        'user_id_2': user_id_2,
        'price': price,
        'winner': winner,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return "accept"

def getBalance(payload):
        user_id = payload["user_id"]
        if user_id not in BALANCES:
            BALANCES[user_id] = 0
        if user_id not in VOUCHERS:
            VOUCHERS[user_id] = 0
        balance = BALANCES[user_id]
        voucher = VOUCHERS[user_id] if user_id in VOUCHERS else 0
        return [{"balance": balance, "voucher": voucher}]

def getCars(payload):
        user_id = payload["user_id"]
        return [car for car in CARS_USER if car['user_id'] == user_id]
    
def getNewCar(payload):
    user_id = payload["user_id"]
    
    user_cars = [car for car in CARS_USER if car['user_id'] == user_id]
    
    if not user_cars:
        return None
    sorted_cars = sorted(user_cars, key=lambda x: datetime.strptime(x['created_at'], '%Y-%m-%d %H:%M:%S'), reverse=True)
    
    return sorted_cars

def getRun(payload):
        user_id = payload["user_id"]
        return [run for run in RUNS if run['user_id_1'] == user_id]
    
        
def select_function_advance(payload):
    function_id = int(payload["function_id"])
    function_map = {
        1: lambda: generateVoucher(payload),
        2: lambda: openBox(payload),
        3: lambda: announceWinner(payload),
    }

    function = function_map.get(function_id)
    if function:
        return function()
    else:
        print("Function not found")


def select_function_inspect(payload):
    function_id = int(payload["function_id"])
    function_map = {
        1 : lambda: getBalance(payload),
        2 : lambda: getCars(payload),
        3 : lambda: getRun(payload),
        4 : lambda: getNewCar(payload),
    }

    function = function_map.get(function_id)
    if function:
        result = function()
        return result
    else:
        return "Function not found"
    
def hex2str(hex):
    """
    Decodes a hex string into a regular string
    """
    return bytes.fromhex(hex[2:]).decode("utf-8")


def str2hex(str):
    """
    Encodes a string as a hex string
    """
    return "0x" + str.encode("utf-8").hex()

def addBalance(data):
    binary = bytes.fromhex(data)
    try:
        decoded = decode_packed(['address', 'uint256'], binary)
        user_id = decoded[0]
        amount = decoded[1]
        if user_id not in BALANCES:
            BALANCES[user_id] = 0
        BALANCES[user_id] += amount

    except Exception as e:
        msg = "Payload does not conform to ETHER deposit ABI"
        logger.error(f"{msg}\n{traceback.format_exc()}")
        return reject_input(msg, data["payload"])

    return 'accept'

def reject_input(msg, payload):
    logger.error(msg)
    response = requests.post(rollup_server + "/report",
                             json={"payload": payload})
    logger.info(
        f"Received report status {response.status_code} body {response.content}")
    return "reject"


def handle_advance(data):
    try:
        if data["metadata"]["msg_sender"].lower() == etherPortal['address'].lower():
            return addBalance(data["payload"][2:])
        decode = hex2str(data["payload"])
        payload = json.loads(decode)
        payload["seed"] = data["payload"]
        response = select_function_advance(payload)
        needToNotice = payload["needToNotice"]
        enconde = str2hex(decode)
        notice = {"payload": enconde}
        if needToNotice:
            response = requests.post(rollup_server + "/notice", json=notice)
            logger.info(
                f"Received notice status {response.status_code} body {response.content}")
        return "accept"
    except Exception as e:
        print("Error: ", e)
        return "reject"


def handle_inspect(data):
    decode = hex2str(data["payload"])
    payload = json.loads(decode)
    response = select_function_inspect(payload)
    responseToString = '\n'.join([str(offer) for offer in response])
    enconde = str2hex(responseToString)
    report = {"payload": enconde}
    response = requests.post(rollup_server + "/report", json=report)
    logger.info(f"Received report status {response.status_code}")
    return "accept"

handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}
rollup_address = None

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])