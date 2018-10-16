/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package pkcs7

// Start PKCS7 keys
var (
	pkcs7CaCert = []byte(`-----BEGIN CERTIFICATE-----
MIIC7zCCAdegAwIBAgIJALYMWoN65+AAMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
BAMMA2ZvbzAeFw0xODEwMDQxNjAwMTJaFw0xOTEwMDQxNjAwMTJaMA4xDDAKBgNV
BAMMA2ZvbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMAyIYgldhGC
mDCEu3kIyXXaPq9dWPrI4NFP+EnY/oPeEXD/q+zL3vPM1nkPw+n67dsqI+vUAkWn
sUZh4r7qHZmSUw4A5hAHuiPhYMe5w+mw1qFtQR4+MTuGXxVcOpDebUiirjTzSzdh
RcUGu76fWTA0tzbmoZEUzIHRuzUFtEMRKMY0W5XyHDcCcXYpStC/BYjvPRaLrsLU
z5rL6uIvsArCNKudiet6HNKTJNCT+5tPaM7Eo/7vZJ8jmmpzvLZtK9126CLdbSb7
24WJsuIV6DqfIvhyDDWnfAL6qc1Z7kFOL+n40UeIrtCrXke0k3FGBNpveZDd0OXC
T5LckXkg7PECAwEAAaNQME4wHQYDVR0OBBYEFClFj/edEXgbPzr7eVBlFaUOQqgT
MB8GA1UdIwQYMBaAFClFj/edEXgbPzr7eVBlFaUOQqgTMAwGA1UdEwQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAGHM/co0eevek5D40ECeMQFgpWYfl91WsaLq37x0
swpfkblNl7q5AXUYpsRqgrCbokPlwuNOIntH24Ls+cdPArlXebI8QVXcIu0hTpvV
Dbv+SH1TC4PfD+VQJkGToPN3lBgHfJnfmBQdUChyrJXBIsEVo6l3F7Xtv1cjI+JB
UpNXStFqEIWlHPbywWc4TUoSzolA0cEj3N2P09jdmn1CS+1Nla+cl8/BbImBibw6
rq7vs1knhS+14gyocIVydhcEfaUVVq58zVHBtz+gnMoblCwibAjVKeG64VoABcjX
xOjgN+wtzZdBzTEojjQFdDJ3wD/EBSg6S0Crw4eOaK/YzMc=
-----END CERTIFICATE-----`)

	pkcs7CaKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAMiGIJXYRgpgw
hLt5CMl12j6vXVj6yODRT/hJ2P6D3hFw/6vsy97zzNZ5D8Pp+u3bKiPr1AJFp7FG
YeK+6h2ZklMOAOYQB7oj4WDHucPpsNahbUEePjE7hl8VXDqQ3m1Ioq4080s3YUXF
Bru+n1kwNLc25qGRFMyB0bs1BbRDESjGNFuV8hw3AnF2KUrQvwWI7z0Wi67C1M+a
y+riL7AKwjSrnYnrehzSkyTQk/ubT2jOxKP+72SfI5pqc7y2bSvddugi3W0m+9uF
ibLiFeg6nyL4cgw1p3wC+qnNWe5BTi/p+NFHiK7Qq15HtJNxRgTab3mQ3dDlwk+S
3JF5IOzxAgMBAAECggEBAIuy5JSlRhCsMBr0H6B2NpknLXEiFM8Uu/Tof7yNsVIA
VAUikcDo3wGu3iXYw7qK3eDz3HBKBezDWyOhesLyQNmjdiMznAYC19XEuCf0auat
1xQ26aIl6nstzGcmRpuOUTj+pklunjl+xsvTfRutj5Jufs21DbL6vzuNStnbb49e
4xR3nVENp2tquwyJDrZnaWgoGmQ8LRS3jiBoDsHaGfjtT9K4BAJ0/e4WHGp5UkQc
oiaVQPFb5DELKjg2Z54QmAT28n4p23egafdUKtxO0rNYK1BDmURumrN1JsQ3lRRe
CCspepInay2Rz6Ca9p60lLc+IM8JiwsDn1oCJ8bSaQECgYEA4eizUQHvoDQapS7J
59MUyhHn9Nq9UCxyM/BvFstpR/cAgYHSh4jqJAXKnDAW+FZH4CNUdK0j+mnVXCxI
BrkWRy1+vBONkwtm7JhShdiMEivRL5dTOgPpEPq54XpjNN/PSQFYDtMGpqX4FrWz
7DBaL94ps/JkTswV9gu16U+sIOkCgYEA2cvXUW0xXYuW1FgIHZUCY8tfO0T+Jhca
FepYcp1AZjZTnO+U7mxQ/EmMRBfppr3dxprYo10/Zp0B6d9/WqYrrKjWk4QJA0Po
2LNmf8YuauMLQ/eDwnr2CKdkLM/ozx0p4Yy45ANMJ6dUsHAhwwoWnOGEC+1lhuQX
C3zIGzoEpskCgYBibGjbrVVCXhER0J3E89EF7OE7a6W5bXPgLyunKb5XzUSaJ/6a
cEtaoG9Stxz621R7Uck1AE5BhqSfgOdsjm0nW6nwtTAkVX5lLEQf7mWwcQi1jF+F
UjjT3fjoRNM+MRh1fTFpXAV0y7CX7FhUWgig/FD9Bmkvb3lN9nIuETk0KQKBgDTW
+5pJv5xObX1/Dhj/OeE0Shp7Fp3vJOkEPgkwlZs2uvpsNdnSdaN/xIQQuSM3FUNF
9iFMUkF2/ivbiW5YumfdXpHTisw8AZXxkICXeFN+WhFXT6QzaNWYpvkoR/dXv/10
wravBh7ovedAjTBgljPhksPCCMu9MsoasAHLBa3hAoGAZz6O8uMJnjQ5pVRRMiVq
zrpoh7sLQxjuyd/XJB8WlL4BGHvXBnWJxGxWmaAaAqGBjMgLfL8dxcgj4IJ/Dg/3
P/UtRJFlqlBO3GjH5361wx4Ic+81OHowTexmk3S9sg3ZQGdA6GpXeCAagyESg+Nk
sVMq14Ak/cGIAr4/eq2/gQ4=
-----END PRIVATE KEY-----`)

	pkcs7ClientCert = []byte(`-----BEGIN CERTIFICATE-----
MIICmDCCAYACCQCzwnhULec2xzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANm
b28wHhcNMTgxMDA0MTYwMDEyWhcNMTgxMDE0MTYwMDEyWjAOMQwwCgYDVQQDDANi
YXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMerBHjMTOsw3TpqD0
bxvDyNHeuYpfmNYHbcsWa3gt3FZhXAi8HGvwnAIPznKUpVuHO0YY8ltAjn/PvKxL
nkmwnZ+9EgXf54RX8WZbCUeNXI8Yxw0O2O1m3sTaVCYFQ2hRhuWQYORhj/pje4kp
n+981ahlRu1IDd2g4f9k4YFEtcRnPrKYrOAvJd7UjKYw23cRLJK29NzjSowOmZ6V
sLw86b2+NyMjnLONbMAwtaW5BbYaHe0sopR/FZPP56prFtMWZ+Sxm7n0r6DAJtsG
uT+eewcsKlBp4GNwC7EK2v7gwK4ur6gWCSdQ3DL+vcDe8XebExprMkA4Er8tXACg
6Q9tAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAETK1D1HMcXRqq4UpnMerej4WcW2
rllPYqmWp5y65xpWdzwriLlVVAFPPqcjp+dxcbJnn3kxpO6elHHBvI45/oIkuMAV
0twhop6TK7WvzmHiPvwKpkZU3qmkmGu6Jku6DxHQWv9nzYgBJHpUpWCFaA43pwWW
CaZ/oHPiElsFbz2DQmebILfOwlEXKed7cmNykihphbSzu/bq84llYH+IVxUWahDp
I2y/5hlcRKkk3T/DEeVy67PJYoGcbnAiF6XOZXXNKWM/TgN6UrcKafF5HJEJaEe0
BP01vscBD2Ryf1D1HJWgyiFnIdq+vSkWLT64GgNKrLlGRSVjtO3D+3dP5bA=
-----END CERTIFICATE-----`)

	pkcs7ClientCertKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzHqwR4zEzrMN06ag9G8bw8jR3rmKX5jWB23LFmt4LdxWYVwI
vBxr8JwCD85ylKVbhztGGPJbQI5/z7ysS55JsJ2fvRIF3+eEV/FmWwlHjVyPGMcN
DtjtZt7E2lQmBUNoUYblkGDkYY/6Y3uJKZ/vfNWoZUbtSA3doOH/ZOGBRLXEZz6y
mKzgLyXe1IymMNt3ESyStvTc40qMDpmelbC8POm9vjcjI5yzjWzAMLWluQW2Gh3t
LKKUfxWTz+eqaxbTFmfksZu59K+gwCbbBrk/nnsHLCpQaeBjcAuxCtr+4MCuLq+o
FgknUNwy/r3A3vF3mxMaazJAOBK/LVwAoOkPbQIDAQABAoIBAHJzMXu61OWE3vZa
S7jE/9tj6eQqIcNEPnfGAmg4GvpAW7D+3Hy9w8TW7Wh/ey6sJ0DX8nJAJMdLe0qB
JkblAAX1E9W14sfiQ/cdTNcjqIL9DbMmpq5qyOZNRg2WD/neMuN/B7r6IJpjBhjs
qmc798X9qNWXD3THHgfQtyx18+7Kdhod6BP0G/v9ApJdgJh/Gr7r/FhsN5oM4N8D
rnYhyJDsIWRDub+wib9AsFt3eUtNEQgHJb5cb1/QD8p+DYntt3g1xciFFlqbQx+c
DUZtfATznMoYGsAxOvKbVfJIaII3MTA88PNzpMdsj9/pjPkOzDIkYJnyeMwdp1eG
Xve6eZkCgYEA7tZWjxnmnqzHU5hBX2HJzDsY+N32aI1yMglEEHNSN156MzhWdlce
GNpkZCDFQ0UDD4mio2sfy3nQdztjzScCNfcye7UiZA3OHzx4LtzvW+vDOkWhab9J
2wtdqBcpJmLCQRq1pBcnufP44P/as0ApeWeAgQUXyDejikdagrwTLL8CgYEA2yxM
hZPgmD4J+DyAvgIrrQ4q+LAis+IhsYXlSEbaauN0pcB6iB8ttXU5d0PSQiKs/UM5
UzyW6gsCtAS1f39g4iTMCu/AmRU5NGQ2ll8sAnjWaWIqrhRRiAukG2u3IVHRyw9T
6NS84lJeTq8xIIA6rOsrZ216xbqEQj9zDIq6UtMCgYBmXmQ3bciVVkURJX9PnKBb
8zCe6rRE1+uMWsBbtLIWnV4POiSFEI4L5P+Gky05yginzjxxgubb1dhuYnxCYGfo
LY3rzBVzgR9J8CcrHvNRGNpSzamDo8PKKTL5awPuOgI82W/lZy9V2qZf+goJLoUY
Ti6cHky1OnPUPwUiZ+5oDQKBgHRM1W4sQgmHIhMvR8GLtVFnKzY7gK6jV+2zdy8b
Kdt+Ru+Na3e/06luQsgenPurGtBpU4nvpMUcgpqzxPuaw/Y8QGmtPy38LRa39p9k
cR3+sQfKp4soDPt78eD7D3oGyKRPxd7OxEv0GUb3f8IXSQto3udLGNLDXlspAAuv
sZ8xAoGBAOK/PCiWo8zZaXxNSZjvZ1xSTd8VN9LNaRUR5nEIPKUxQ3ebklpI2bED
W72y/gLzquDmJu8ope9Rqhz/1oaPaeing9eCePu3m6PpKUxjVNCK6rJrgQrTTf7Z
LdrG5gies5HBG42czG8b2Lo72vjf2UA3nMkhy206hTR5lC5XtKhC
-----END RSA PRIVATE KEY-----`)

	pkcs7Client2Cert = []byte(`-----BEGIN CERTIFICATE-----
MIICmDCCAYACCQCzwnhULec2yDANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANm
b28wHhcNMTgxMDA0MTYwMDEyWhcNMTgxMDE0MTYwMDEyWjAOMQwwCgYDVQQDDANi
YXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWYj1DPagPOl9F3DQj
EsVVMZ1kTByB5L1ZXDIRAT1vLW5+f8/zRYPXTih9M04dZ3YYvatc+JC3sKYCZndM
oRyKZZldi87eanv4I+CtH5fAA9bw8ArdQmYN63O935zKmj5G9n5uON75TmRtcwKM
d9+zDTGN4GckScTndSgYYM/QCSP4qdOlm41Gjvke4SN5jqt5vBSq5FBcvn7tU9r1
MZIX7X7joUtWfCva/0AHvV6QIvREOexAaUJ1BrTW2jkcDAAIp/FDqYadkbtuhe3A
Qdum9ZDDvavRvxqs9RbYSpbUxsHel+k4VsxafrotCbRqOO7nBiwOh4JmAnE/jccW
Joh7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEUKOALCeaRwZNmoIjJZ2XJuE+O+
9xCleQglEbdlvr9jbH3nSl/xF7Yh3wmc45+lDC2w2wlvthK8yHnlc/YNefiMHd6l
Vemcyzqqlaz8MOxMIynkFpw5w3jAMKM989nPYsWwNlBhQc+nlQtd3tumCJRgRNMH
B1UqSVkNLhhi4nVw3OMhQDcslvCvjQC25+y+FdvJIEh+qNS/xmr+dWCR5qWUEibM
rR09F++W1v7fSSM4gK2aGPqUGaSzHNV8wqBgW922zbdLzg0wTXYlcfShDbGY8zWq
Xuve9eoT97dwcVYIdXzChF9tmtNWRhROhLFkUc57EFfmFUkfeyGKMfZg9kk=
-----END CERTIFICATE-----`)

	pkcs7Client2CertKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1mI9Qz2oDzpfRdw0IxLFVTGdZEwcgeS9WVwyEQE9by1ufn/P
80WD104ofTNOHWd2GL2rXPiQt7CmAmZ3TKEcimWZXYvO3mp7+CPgrR+XwAPW8PAK
3UJmDetzvd+cypo+RvZ+bjje+U5kbXMCjHffsw0xjeBnJEnE53UoGGDP0Akj+KnT
pZuNRo75HuEjeY6rebwUquRQXL5+7VPa9TGSF+1+46FLVnwr2v9AB71ekCL0RDns
QGlCdQa01to5HAwACKfxQ6mGnZG7boXtwEHbpvWQw72r0b8arPUW2EqW1MbB3pfp
OFbMWn66LQm0ajju5wYsDoeCZgJxP43HFiaIewIDAQABAoIBAQCBOZZUAcZb54Om
SKXkvlvUjqOg4YANjCPWyYwkU+sEKQ6Bkel3al+eWK5vSY28i7DUGQBCelJBZ2mp
6LngpvzdL4DSsoNv7h/r4zR7JqACTk4xzX++/1ck7NhHi5KnTXJctBhhuEYvYOGI
V9shcOCWvU0xiCKj7ROTsTsJ9tFNRBpnej5gsN6PjooOENUTcWpEjvUzt+2lYnrk
XffHi6ETigmSPh6xBKJzZ3SLDGREkgiLbIZfDV+BpJ5fS5OAEigdJI00d22FrYAv
VulvEqezlfvkV7e16UrJxhTq4rV/uB7kU9eVI0acXuxbmaxnypt5gMmsAwmo1bQG
D4eIAI8BAoGBAPcJBrw06/kzMMzEONuJ7fG0LzZv0KZLrO6D11jKD8b3/gkBhWeb
A4sDYeVgWAgc8kZDKPhQyK3a765GvAdLH2khjWLe4JvqPvJ5zN8hcgplMJ5eKcdA
mXOe7FCERmt3rW8dgIzj95NNFbfaxCOMDQN3ljZy+OSzAgqMTSoc5HxzAoGBAN4p
4NmtI7YU8SMl6hnfNBPwhSHRBmI62mbKKu7LnYnO4oS8AaaqwZm9UWeZL1JmZV7o
kERswGvcHGrNOmEFdMeJL6Qb96qJrInvfhtVvRwuZSUIPLf/W8WfStS79rAQzToZ
nwIQmEcNX9QCZQjSnfPpMEabXvzORmjNJpqKQwnZAoGBAJhrZVByhrY3M4DkAQDT
1ZAwUIER9Hbmckin6BLMeXeWQ5Ni8OC/8CuxZpGUJDy9P27CuWCc13UNhJzO3+zQ
GQ1Qul+qjIMmwLfzFskFZcusK5dLGhPqc8O25q+3LYvZR5UrasmDTpoAEcpinGoi
W1UsT+5AefkBydygPGwjb4apAoGAFBsAIVL8915/0Cl/PSYpBWDv+3Z6OGuRFlpX
dlLxB+a0M0T8dUPgz3QFqPWBBdkEdYlgfQDGjTxXSgcWsG8Y+XHd4OEzEbjx523I
INsqiSFdv/M144T1njXjRMtZ8OckW4y0CjDMRynbsUkiMaE18Dv7RXiMKR7V2mgu
hS/cD0kCgYAo5WfozQQt6EWfNJ9Kqn49j79iRIjhTpyyz+ZxxoYynj4K46dg3Kch
15f1P0PnE1kUz0UWvsKiHPJ5eGS8q8a0OPt654fsHm2GrFhTMgIDWHwAziR8vYZ/
uFC+qBqMs3fz12xw0mLEmbNYvp/zWBGDaFwF23A3OCxwuGqLKWM7aA==
-----END RSA PRIVATE KEY-----`)
)
