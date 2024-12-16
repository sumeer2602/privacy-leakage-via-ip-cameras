import requests
import os
from datetime import datetime

# Define the endpoint and file to upload
url = "http://meari-oss-us.oss-us-west-1.aliyuncs.com/7e/v/1004379268/1025661902/20241124/sc.png"
file_path = "sc.png"

# Check if the file exists
if not os.path.exists(file_path):
    raise FileNotFoundError(f"The file {file_path} does not exist.")

# Calculate the Content-Length
file_size = os.path.getsize(file_path)

# Get the current date and time in GMT format
current_gmt_time = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

# Define the headers
headers = {
    "Authorization": "OSS STS.NUVr8uvB4PJkU1XtCzBSPhALY:BWOibcBJRe0iYnvN1kKVfMssgag=",
    "x-oss-security-token": "CAIS3AN1q6Ft5B2yfSjIr5bjOYLBm50V54iAVxfpkEMvTtx8h4Tnuzz2IH9LeHZqBe0esfU3mGtS7v8YlqVWRpZfRHf4VvF36pkPXe8ZllSb6aKP9rUhpMCP3wLxYkeJHKWwDsz9SNTCALjPD3nPii50x5bjaDymRCbLGJaViJlhHLN1Ow6jdmh+GctxLAlvo9NgqBKzU8ygKRn3mGH",
    "Content-Type": "image/jpeg",
    "Content-Length": str(file_size),
    "Date": current_gmt_time
}

# Read the file content
with open(file_path, "rb") as f:
    file_data = f.read()

# Make the PUT request
response = requests.put(url, headers=headers, data=file_data)

# Print the response
print("Status Code:", response.status_code)
print("Response:", response.text)
