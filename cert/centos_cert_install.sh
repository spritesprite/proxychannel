
# 1	Install the ca-certificates package: 
yum install -y ca-certificates
# 2	Enable the dynamic CA configuration feature: 
update-ca-trust force-enable
# 3	Add it as a new file to /etc/pki/ca-trust/source/anchors/: 
echo "-----BEGIN CERTIFICATE-----
MIIFdDCCA1ygAwIBAgIBATANBgkqhkiG9w0BAQsFADBZMQ4wDAYDVQQGEwVDaGlu
YTEPMA0GA1UECBMGRnVKaWFuMQ8wDQYDVQQHEwZYaWFtZW4xDTALBgNVBAoTBE1h
cnMxFjAUBgNVBAMTDWdvLW1pdG0tcHJveHkwIBcNMTgwMzE4MDkwMDQ0WhgPMjA2
ODAzMTgwOTAwNDRaMFkxDjAMBgNVBAYTBUNoaW5hMQ8wDQYDVQQIEwZGdUppYW4x
DzANBgNVBAcTBlhpYW1lbjENMAsGA1UEChMETWFyczEWMBQGA1UEAxMNZ28tbWl0
bS1wcm94eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANiuppEbanTv
iCs47AFIAy+AVXDhaInal4fGmN+kG1txO4YPygKGrdjokCZtkL6ZK61izFg6BLX+
p65j8wnAPZPZr3Zu5vlcDM7baO9ddxtnXm/fACPEuMIvgmG7zxE9CeX3LY7tsq10
hg8uKMnYGTy5Ce0hkuYn8Od0yHseGFWCmaCAHIcshbvQFxPGn42X/zWrEHDEgWtG
fOlamBBTSbNza11H8udLkXlr+N+vv/P/eKjpeIf/xzPCdiUOxdD+NHCeeSgho3Sm
P0T6ia4L7MVW0XUg7CseVVh+9TddO6QefmM1+AsWU/ektD+cUMtlWoDXE8idlpoZ
cMVJfq/6Sa9nG280fCPjd4wFLqbR67BHQkoPjQ1vmRgs4xvD04m796dRPpTDepb/
xvTTMcwgAC5tur/E5SHpr8hx9X6xGPfUUMiKyBQlSgLH4V02SjAmScxqt5AWZcT/
syLHg7BhjxwBGoCwcE8zWHCJarQ0t28Z7ptyL3DXPaJ7Vd2CvLJrekvtnm9B28aU
9KOC9JL3DKzFaRrhTYb0VNLfoLV8kRJCzZI6HAwiKcAAEIXi8on6YwqLvEIxo5AL
0gTeIf/nJU2W4OY640fIdwEvcaH4Wj2bKMRaTWvQGM1TJe4hoCN/c3mVopotCb44
IGC5R0XmVImVxZmdyCXJAfY1jYrWHA2ZAgMBAAGjRTBDMA4GA1UdDwEB/wQEAwIB
BjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSfjEyzebvckLQu+eZjlmJF
W0/ZmjANBgkqhkiG9w0BAQsFAAOCAgEAXHGvSFwtcqX6lD9rmLTPeViTIan5hG5T
sEWsPp/kI6j579OavwCr7mk4nUjsKFaOEzN78C4k6s4gDWWePoJhlsXB4KefriW4
gWevzwgRTrIlaw3EDb+fCle0HcsCI/wwxDD8eafUxEyqBGrhLJFiUIxvOcD+yP2Q
mX3Z89Pd38Qvkb9zneJdXo2wHMq0MGKlTPdE04rg1OsuPNnSwRhtem9/E4eCtumF
JoQEQtp440wpvrbZljR18Ahd+xNh6dyaD0prnrUEGsUkC1hMb3nUWmw6dZEA5rCv
8aW5ZMm9Jr7pW7yzrm8J4II1bY5v6i7+qvOFDAf1nEnVshcSCiHu6xzgtwoGtsP8
mSOquiWwiceJL6q8xh6nOD3SYm2mZwA1n7Nl3mRJE/RgbwJNkveMrmZ6CKUm3N/x
eqd5yhTLsD7sf3+d4B7i6fAZ+csccWaDuquVI9cXi2OoMKgIFeeVwJ1FCeLY0Nah
nPlNUA0h7xKeDIHtlGsSOng6uiEVVVXGS+j9V6h+Z55AsuOAoHYOBDoXfr0Y4Bww
irCRNyFcDrKoyILOOUiPxoEcclrwUBTB78JxVA8xKTbAh0aZQRZOZOz49qF4gA1d
1riiUHJIG2sD+54UEdFoR5nhZ4/RLGqQ/Kmch5VnPp7De4OzSMd/KkQDWEjR+AA1
CDPlL4gNB6s=
-----END CERTIFICATE-----" > /etc/pki/ca-trust/source/anchors/mitm_proxy.crt
# 4	Use command: 
update-ca-trust extract