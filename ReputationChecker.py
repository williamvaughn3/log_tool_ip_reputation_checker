#!/bin/python3.6

import argparse
import requests
import json
import ipaddress
import yaml
import os
from multiprocessing import Pool

DEFAULT_CONFIG_FILE = "config.yaml"
MAX_PROCESSES = 4

class ReputationChecker:
    def __init__(self, api: str):
        self.api = api

    @staticmethod
    def get_api_key():
        if os.path.isfile(DEFAULT_CONFIG_FILE):
            with open(DEFAULT_CONFIG_FILE, "r") as f:
                config = yaml.safe_load(f)
                api_key = config.get("api_key")
            return api_key


        # Query the AbuseIPDB API to obtain the IP reputation score
        # https://docs.abuseipdb.com/?python#introduction
    def abuseipdb(self, ip):
        api_key = self.get_api_key()
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }

        with requests.Session() as session:
            response = session.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            response.raise_for_status()
        data = json.loads(response.text)
        restrucured_data = {data["data"]["ipAddress"]: data["data"]}
        yaml_data = yaml.dump(restrucured_data, explicit_start=True)
        result = yaml_data 
        return result
    
    def sans(self, ip):        
        headers = {
            "Accept": "application/json",
        }

        session = requests.Session()
        base_url = 'https://isc.sans.edu/api/ip/'
        response = session.get(base_url +  ip +"?json", headers=headers )
        
        if response.status_code != 200:
            print(f"Error querying ISC SANS API for IP address {ip}: {response.text}")
            return {"error": response.text}
        try:     
            data = json.loads(response.text)
            restructured = {data["ip"]["number"]: data["ip"]}
            yaml_data = yaml.dump(restructured, default_flow_style=False, explicit_start=True) 
            result = yaml_data 
            return result
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response from ISC SANS API for IP address {ip}: {e}")
            return None

    def otx(self, ip):
        headers = {
            "Accept": "application/json",
        }
        with requests.Session() as session:
            response = session.get("https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip +"/general/", headers=headers)
        if response.status_code != 200:
            print(f"Error querying API for {ip}: {response.text}")
            return (ip, None)
        try:     
            data = json.loads(response.text)
            yaml_data = yaml.dump(data, default_flow_style=False, explicit_start=True)
            result = yaml_data 
            return result
        
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response from ISC SANS API for IP address {ip}: {e}")
            return None

    
    def check_ips_reputations(self, api, ips):
        results = []
        if api == "abuseipdb":
            with Pool(processes=MAX_PROCESSES) as pool:
                results = pool.map(self.abuseipdb, ips)
            return results
        
        elif api == "sans":
            with Pool(processes=MAX_PROCESSES) as pool:
                results = pool.map(self.sans, ips)
            return results
        
        elif api == "otx":
            with Pool(processes=MAX_PROCESSES) as pool:
                results = pool.map(self.otx, ips)
            return results