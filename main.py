import re, json, urllib.request, os

pattern = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)") # detects IP addresses
limit = 3000 # number of attacks to retrieve geolocation information on (limit 1000 in a day)

IPs = [] # IP of an individual log entry
attacks = [] # IP, city, region, country, and organization of an individual IP
countries = {} # attacks by country

os.system("clear")

f = open("auth.log")
log = f.readlines() # contents of auth.log
f.close()

f = open("countries.json")
data = f.read()
codes = json.loads(data) # country code abbreviations
f.close()

for line in [d.strip("\n") for d in log]:
    '''
        processes log file
    '''

    matches = pattern.search(line)

    if matches:
        # if there is an IP address listed in a log entry, append it to IPs
        IPs.append(matches.group(1))

print("Identified " + str(len(IPs)) + " IP addresses.")
print("Will process " + str(limit) + " of them.")

# prepares attacks.csv
f = open("attacks.csv", "w")
f.write("IP,coordinates,city,region,country,organization")
f.write("\n")

for IP in IPs[ 0 : limit ]:
    '''
        processes [limit] of IPs
    '''

    # requests and parses JSON from IPinfo.io
    URL = "http://ipinfo.io/" + IP + "/json"
    stream = urllib.request.urlopen(URL)
    data = stream.read().decode("utf-8")
    j = json.loads(data)

    # removes commas from data
    coordinates = j["loc"].replace("," " ")
    city = j["city"].replace(",", "")
    region = j["region"].replace(",", "")
    country = codes[j["country"]].replace(",", "")
    organization = j["org"].replace(",", "")

    # updates attack counts by country
    if country not in countries:
        countries[country] = 1
    else:
        countries[country] += 1

    print(IP)
    print("in " + city + ", " + region + ", " + country)

    # writes attack to file
    attack = [IP, coordinates, city, region, country, organization]
    output = ",".join(attack)
    f.write(output)
    f.write("\n")

f.close()
print("IP addresses and geolocations exported to attacks.csv.")

# prepares countries.csv
f = open("countries.csv", "w")
f.write("country,attacks")
f.write("\n")

for key, value in countries.items():
    '''
        writes attack counts by country to file
    '''
    output = str(key) + "," + str(value)
    f.write(output)
    f.write("\n")

f.close()
print("Number of attacks by country exported to countries.csv.")
