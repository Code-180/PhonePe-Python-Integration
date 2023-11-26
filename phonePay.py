#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#LIB
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
import jsons
import base64
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def calculate_sha256_string(input_string):
    # Create a hash object using the SHA-256 algorithm
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # Update hash with the encoded string
    sha256.update(input_string.encode('utf-8'))
    # Return the hexadecimal representation of the hash
    return sha256.finalize().hex()
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def base64_encode(input_dict):
    # Convert the dictionary to a JSON string
    json_data = jsons.dumps(input_dict)
    # Encode the JSON string to bytes
    data_bytes = json_data.encode('utf-8')
    # Perform Base64 encoding and return the result as a string
    return base64.b64encode(data_bytes).decode('utf-8')
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
MAINPAYLOAD = {
  "merchantId": "PGTESTPAYUAT",
  "merchantTransactionId": "MT7850590068188104",
  "merchantUserId": "MUID123",
  "amount": 10000,
  "redirectUrl": "http://127.0.0.1:5000/return-to-me",
  "redirectMode": "POST",
  "callbackUrl": "http://127.0.0.1:5000/return-to-me",
  "mobileNumber": "9999999999",
  "paymentInstrument": {
    "type": "PAY_PAGE"
  }
}
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#SETTING
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
INDEX = "1"
ENDPOINT = "/pg/v1/pay"
SALTKEY = "099eb0cd-02cf-4e2a-8aca-3e6c6aff0399"
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
base64String = base64_encode(MAINPAYLOAD)
mainString = base64String + ENDPOINT + SALTKEY;
sha256Val = calculate_sha256_string(mainString)
checkSum = sha256Val + '###' + INDEX;
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#Payload Send
headers = {
    'Content-Type': 'application/json',
    'X-VERIFY': checkSum,
    'accept': 'application/json',
}
json_data = {
    'request': base64String,
}
response = requests.post('https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/pay', headers=headers, json=json_data)
responseData = response.json();
#print(responseData['data']['instrumentResponse']['redirectInfo']['url']);
