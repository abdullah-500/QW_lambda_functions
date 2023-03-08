import json
import os
import logging
import time
import sys
import re
import boto3
import datetime
import time
import email

from inspect import currentframe, getframeinfo

import base64
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from Cryptodome.Cipher import AES
import requests

import mailparser
from bs4 import BeautifulSoup
from warnings import filterwarnings
filterwarnings("ignore")

raw_mail = 'Subject: Terminal Email Send

Email Content line 1
Email Content line 2'

mail = mailparser.parse_from_string(raw_mail)

print(mail)