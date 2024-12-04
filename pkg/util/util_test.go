package util

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test certificate created with an OpenSSL command in the following form:
// # Create "root1" certification and "cert1" certification signed by "root1" certification.
// openssl req -x509 -nodes -days 365000 -newkey rsa:4096 -keyout root1.key -out root1.pem -subj "/CN=oauth2-proxy test root1 ca"
// openssl req -nodes -days 365000 -newkey rsa:4096 -keyout cert1.key -out cert1-req.pem -subj "/CN=oauth2-proxy test cert1 ca"
// openssl x509 -req -in cert1-req.pem -days 365000 -CA root1.pem -CAkey root1.key -set_serial 01 -out cert1.pem
// openssl verify -CAfile ./root1.pem cert1.pem
// # Create "root2" certification and "cert2" certification signed by "root2" certification.
// openssl req -x509 -nodes -days 365000 -newkey rsa:4096 -keyout root2.key -out root2.pem -subj "/CN=oauth2-proxy test root2 ca"
// openssl req -nodes -days 365000 -newkey rsa:4096 -keyout cert2.key -out cert2-req.pem -subj "/CN=oauth2-proxy test cert2 ca"
// openssl x509 -req -in cert2-req.pem -days 365000 -CA root2.pem -CAkey root2.key -set_serial 01 -out cert2.pem
// openssl verify -CAfile ./root2.pem cert2.pem
// # Create "root3" certification and "cert3" certification signed by "root3" certification.
// openssl req -x509 -nodes -days 365000 -newkey rsa:4096 -keyout root3.key -out root3.pem -subj "/CN=oauth2-proxy test root3 ca"
// openssl req -nodes -days 365000 -newkey rsa:4096 -keyout cert3.key -out cert3-req.pem -subj "/CN=oauth2-proxy test cert3 ca"
// openssl x509 -req -in cert3-req.pem -days 365000 -CA root3.pem -CAkey root3.key -set_serial 01 -out cert3.pem
// openssl verify -CAfile ./root3.pem cert3.pem

var (
	root1Cert = `-----BEGIN CERTIFICATE-----
MIIFLTCCAxWgAwIBAgIUfVKJjmDCrxB6a4GfPxF7QjP67vwwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwab2F1dGgyLXByb3h5IHRlc3Qgcm9vdDEgY2EwIBcNMjIw
NzA3MjMyNzUwWhgPMzAyMTExMDcyMzI3NTBaMCUxIzAhBgNVBAMMGm9hdXRoMi1w
cm94eSB0ZXN0IHJvb3QxIGNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA8a5ieYCOmxkKT5fnZbLe5zWun+zNVnIGJOrrayg4esJ9TXfnfzQJE6sC+7ty
C5CGmueZqNAiYBriXzLoQwqtb+wVORH6TBzn2rNQonxMXB4rGaHX9Z1+bx3a3WKi
nDY1oERDeAeDOS42QhJIoSnYMYVHWeKdYw+xveLPjtqiN7pj7bPB7vpyFRO0c3r1
rN5Y3bB2fzb2bYUmt8A3y+4/pREXMiGN610SVFHHw8X6WtbeuM+w4JKcp2jzFaGU
AocvbFcNNth6jiM9a4jERjZ+VV/rvvGAx1Ucp3a9kcHc9s2r0bQV82U3KqO2RNP4
M5y9g+TKMttaDMp2PC20jpWwfJ/wfmFWk6QK0oJU6FlcaPOop6YzIaIdOP6qXVEv
Irg5yheefafsH79cV09Srw4EEklretIm/p+qLWsi/eacF3yG67nznp5uOqqyeDg0
Za1bOvOT14m4yJvM6uyykYLkNqXpbZ8HEux9jwPoWfAWRVJfFt8aPCUb4vT3S6ps
zA1izlA+j3hbBHfrOT+zFdrFy7Urr9d6lAhur0mnog2e/QN/7cFLSNDZwLntatcj
BTWJ3CZdKBKhfthlCJ4at6BS+Yk7HZudMaJCuRjk/0aqoeb7LPjtZwS8YnYgACwn
Mq4J38BSyuTxkD3zffxnnaL41ID4mmMK15VhaETUZfYlVocCAwEAAaNTMFEwHQYD
VR0OBBYEFCmVnz9yP/WllHiEZeE8Y63FQK3iMB8GA1UdIwQYMBaAFCmVnz9yP/Wl
lHiEZeE8Y63FQK3iMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB
ABdSLp6If5CBv26LdMWcMXNq0t8FRRx8tSGZr6aWQWxYzb4L2yWQaZIYsEnlqTVI
f6yQWevURx5m7yxnZovM6ovF1D/ivAdgYJDOIuT9eHIJ5DFS4ayDmUbmtzzWsH1u
2qaMQnWSZjwP1ISgNcCVlICclW5rwIKGLeU9NRxNrNLoDCsPFneOR1GWYG5i7EES
TvhynThBzhGYICPrIXKLpZEmYJb0sxOqw7URorwHLcAd4oACJ5UbN87QvHN9tc99
+H2zJwibaxbg0bxOhFCmfbPuSQ2sgn/Ff80utpv+yZ/WDmIaSuA7TUXT+qIovHSi
z0ZbR2ytzflzXZrj6JEN1R4QJ2UTvzcYBNbT+UnNpMrqGk9HO5v0D/k0QoN4XtCv
YX351kePLY+69mTzwjWVjdH1aZh5ROh4i3Zez1+aZZuZlOoIOWbm1EzlmAYwlQ1L
OArpFJ7vc1Xx6/q9uoW9bkZk4tYNRdgighCDBDv8JnIHl+ZUPAJm1dnnv7reyfPy
wgySqqf9K+LokNpEsVS3sQYa5HRgF4rGYPBiOxnHBRb+7PnGNK9p8wI/FAfbuXJN
oV3sleVSP/U9sr/1q8ThUy7w9MW8NOT4EKbQh5Ph5L2aafsO+LNn9Ly9vZgxy5Dz
HJcjgKpeXzKhwMtFToVEkkIx+VL0kcRxou4XAF2wltck
-----END CERTIFICATE-----
`
	root2Cert = `-----BEGIN CERTIFICATE-----
MIIFLTCCAxWgAwIBAgIUf67dNKjgAWyO1n66bTtAS5eWnyIwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwab2F1dGgyLXByb3h5IHRlc3Qgcm9vdDIgY2EwIBcNMjIw
NzA3MjMyNzUxWhgPMzAyMTExMDcyMzI3NTFaMCUxIzAhBgNVBAMMGm9hdXRoMi1w
cm94eSB0ZXN0IHJvb3QyIGNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA2NFh8OB0/sAt/bys5L2gqmOv9j45VleZNUifPR6CAyaEnGUjRAEYR+ncwc86
9EgR+w/RguUncLKk9U1Fq/Og4/oXI2F595Ryf2Vqxl9wW55AYWIBgep39u0vmWFS
MacQISkRs5zQNNu5D+wQDSfC5u8zkXXCAd1yUt8W5JLieg9PtT3yHWSVRLfZgs7+
285B9xDE04z/XmaF1gP7oVtATswO+ssV68XiiKK5n7BfB6zQbDIQGrSLevGftDZ9
R1BS6wtE2wzzuZoBQ6bZSWrudSf9DIzKZsuphsY42tE8q9Rpur1tFVL7mwC6rYBQ
s4mw+qKj1Wto6O0NQTZ+E4r0dcwCZIa8MP8tYyJylozai0+7QQsdzuM7V1PuvmCQ
8XiBdiLAN+vjMN+7cqvyzA0TtWPy7sE/5kc+L+FnrSGllXc3/YytY7t5bfr3CPwO
tQuTYVPqr3lpAnbTz4jhplT9NXKdFGFwagk8V4si/GwnW2fCpMw1Kcuy+qVOI36x
O1KJ8mBe6vxzfYIYHV22EniWvmA6GOEcQM5xUsYbSsN+IkC3OVIgn2MbBaVQ2KgP
Xzrfja7b0T9mqAvWexxUKrlWrQ+igVQNfxrSizFRwj/WlKh/h4sSbmiMTgN6Dpj5
8bOogWkH9AE0UfHYxN6GHHo9ZMRPrreNL3YTCzreSttHHcMCAwEAAaNTMFEwHQYD
VR0OBBYEFJGlZ2LTzaDmI36BTXYW5IpZy6jZMB8GA1UdIwQYMBaAFJGlZ2LTzaDm
I36BTXYW5IpZy6jZMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB
AKejioTBUlfJeqX5hUnN882xOR/gwitr1/MNVi8a0Y2fXvFWYrZjzYCcYqXPi0Do
VELZaojqHCi9BvO6nQfxK6I/Rf7FZB/kEQMbYF4F5FEXD6DoSsV8Q5sFqwY/ry2O
1Q7xCn1WF1lVUXzkd0aiT1p4N6pj+iTIVgiEzR00lmYYMP/UjThDyQ7KqK2TwVeX
9EgSXNFGXz1D1uJkskhQ+3fiVWmwIfI3WZo/so3VXiNFB04s+le2/l49DQ6cmSd/
+OGsTur09m7GtsFSD00JV3N5znTRXpxgX6Rgt1WpDPj6GqGPuJK2KZ5fFwuiqXs9
GUXXcJeadw2i0BgEJmiIputRLmsdNyBKHLxAxj7zcQVGJ5ZH7Vmmdo0oVWva/t4f
dJ7dl6YVm/xt0+kuF3CsdtsroK+Yh/tp5wslOyzX5B4tOJo0HZpQhfJzYqeleZG4
mmu20Q5sWqggb0WNk1GoHIlpiObgY38KfnNSZ5Ra/QuXLF3QM2NdK5bT1iNFfPG3
fQklEouz/2lqZkRhsKSeXFKQ+h8GtNevKwFg6y3wWvH62WF5mTe9eyUE9VWl64y6
js5ESoVXA+e+QfsMsJrI5XfLV1O8ZxXKAVrYxBnC+WQbrNOjI7VBkjcn/QDmDjBw
sC1lo4YZwxEQ/bE0kEWI7PT/Skml4bTLw0jsgXNV9Nd8
-----END CERTIFICATE-----		
`
	cert1CertSubj = "CN=oauth2-proxy test cert1 ca"
	cert1Cert     = `-----BEGIN CERTIFICATE-----
MIIEwDCCAqgCAQEwDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwab2F1dGgyLXBy
b3h5IHRlc3Qgcm9vdDEgY2EwIBcNMjIwNzA3MjMyNzUxWhgPMzAyMTExMDcyMzI3
NTFaMCUxIzAhBgNVBAMMGm9hdXRoMi1wcm94eSB0ZXN0IGNlcnQxIGNhMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyaGEqDJZjaQybLPbBTfgdl8RVksT
FPdThWaL6vVU9Tsmjk6KC+TcQmV8OXTi70QfxciqFvtoCR5IwayAwztHresRJb5e
5IrOC250wSai5A4t3dF/VWSkJ8qE59L8Km5rR7AcooT32iFXHr5dmXN4qkbsI9iI
PfGo4e/zxC+bcBwQVScTDOrOamqUiLNVHE+kQZykwpshlShiqmpVq87FH+2ceZ0Q
0gST3+AUi+E0pd97AU1a/SO9MSKr0XwZxhrGag/eowwB0S2LHobLJouvFsbqUYnS
4E6Jby1AUIWBeJ2v4xMw7Y2Hhu42t0BRw+SiZBS59HRpjM2zDptGjxWJFjNsQ98/
e583Gn7foCETaDSpoOzFvnP3qNp6dUkJIt4DJRzRPMBXVXzQ8kwc8EHISQFLb4t9
reS3NQgEPFbSoxZRS2e5zpopuFOekUejT+57zib4XalOdVNZi7CFbF4OZuMGXYsj
IgaIatcon8ujk/f0LqUfCSyNFXLpO10ZKpV5z0QGXyMYfLjImUyHHHs6VPPc3AL0
cCspspx8ihnOHE9pD0ljfbQI/mdwk0wZ5Cg+AOWk2x1nlzXUV4aHtv9VLOaUb66u
O5o6nSUu/nEBwsLo5xiXur63V0GEolj+Ia7DROEyofX/G8whlAxHT4IqAit2CVSA
CmVWz+WrnHrSvx8CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAjHLcBlx/6GarXwTw
+fgiDqs4CfOLxUKIfrO8+gHxFEBSYjr194lccK2AlzneCDs5E4qyspaxT1mBm2D0
K4O8lhEoHxgcWsWEejNwfj+tcicV1G9P31mYK1XyexBa6oTQ12WkmE7QhEHQ0aW8
ldU6ntf7soIbh3JXeoyNuDrth/M4QO4TcgZG4svaRUraoATov2J6D2SyJBqrzEK9
s+JwGdY7PEHCx7NPcqZ66Kf1b593aJlQiBUKDAkrPXAYVoEJesLq5AD2j+GxOydt
gBncgeV/3A8IKwkiWcVYkMhe+tW59Q19j2t9BFyDkRECpOeNTR9OcQ1mwpv/BfY3
zLtkzYhls6NvY1OVD8yxKiqYBdv/PrtpcmLbnWO8q1a8UzxlzFLCAzjeqqs9LQQZ
RafejyWax79chjby2DrvgILxgyNiR8NZu68ARziKdCsAQZR/R99rYtRYS/PvYEUy
WA+NNQQzq8KOuyTUxx9OYtBq93WFpnOE8/jrOu+KCmrGLXBS5CYOviu4q6/wEp0O
swFvtQb0ZESaZ65NxC0uSQLTc1E8j2PmQk7J+bcVHFD2nCEHgRtAx0NcdnUPPi4s
Qht3aWEb8fxeWqDCFzn2G1yFCe3bv3T9OoBvFLVGu8al1puAM2fypkTlKb5s7HEl
ZZUrUbOKkforJJnoiPXIlG/Lka4=
-----END CERTIFICATE-----
`
	cert2CertSubj = "CN=oauth2-proxy test cert2 ca"
	cert2Cert     = `-----BEGIN CERTIFICATE-----
MIIEwDCCAqgCAQEwDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwab2F1dGgyLXBy
b3h5IHRlc3Qgcm9vdDIgY2EwIBcNMjIwNzA3MjMyNzUyWhgPMzAyMTExMDcyMzI3
NTJaMCUxIzAhBgNVBAMMGm9hdXRoMi1wcm94eSB0ZXN0IGNlcnQyIGNhMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoyM+YiNabREpTjoZ+pl2QimTTwnQ
AxzotBgRg0/y2pIw6mLYYLpfAlSQO8340D1J51GT5IjVOkbJPEQ/92jf7lX5plQd
8ogc7Y3N4drpKQdPr364mxy0o8cr0d4H+rXBYpWy/JiUEQ+ZsrGjeX1URALkdOcO
SIUAL1UhMysNUXGP8OttP9+TKlZEInFS6bZea+5Hm7SG/3upFfMd9SVPIbw8ixzD
0w9uCrmQ89hy/qSarAn5PFSY2aVpCxGs4Nbs9tG150Y54GgnIjFEmb65EKsHOGf8
/XqWg1Y426a7K56OjwxJGKEc2C0vWxNhvOapNcL7O9/2omkqhh/VRDkNiPYq7byi
/AjAm9tqu08fIHJb8OTa08SPxIxOEd8spdPCf3C/NmtAiuUjGbFlgP5SVAuLdeiT
noaJEcGeungkmeZmdgKlvEFbObfVe1kIqyxSx9wVofnmAMyl7rga9BOIwAECYPOU
iAyq7pFswDUISiulDnKBusJShh9IhQO+kbmw3RL+wuZk25vd0WqeCVgB1zPvyAPs
L1JcIKRyVf3OW4zv00AO5sqdUoUg06si0jzGGFSOoyOESh49Pi6ie2lWBLJRvRVQ
fMqEdSN8xSWvEMgFfIDc/VO2zlT17Tj/S2KRMdgaArcKYQoIRSC91vJc4tvFgNkQ
lan6RXy9GG9+UQkCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAbgARj/AUE8GKubN5
ycg1yWr95dRS/YeOWEZHnFL4JO85IYXgH/KndgtadM2UQUUqeGfTZ2KIlNrAgraS
tjPruxVQq6NwzP6pj3konaoCeGs2kiepJBHgZ5c/YUT7CVjInUMOz3bxqMxVDRda
ZuewaJp6IMZGeBL0Oeb2pXVFGjKehkGBlNr/nuH2tvFVVRPMu/ooqrHhyj0+WHbD
NYVTNAnwHqFy4mNKOH/MwW7KGUORvAQtR1n8yzityGW1q//KfRuwqsn+ZCwnEe82
UiYGZKAL1pKZDWtp6QdbEt2sF4U7HFAvhvWekRd9gVanMtILfI9Sosbo9HLtMvyq
Pq0fIPFdxOj6G5vRkJqGnHzF88l1oyBQXdw16CNETxj+LyhrzlKTwgy5GQz1Eohn
4N9rfnCp5salP9naH5eRD/dBFA0m/yhYWF5MeRlNSbuxk3jxuZ7/HsbxG5zczEuZ
VfUybBMnJC6A1ZML6fzMv18vj8t6Ub8cEdDIP0hCYlLTw9DY5eOJrR3jxdRZqOQ6
pk85aEOG5fyGV+m7VWXl9l2tt9xALxTlMe0WJAIkRvfUsbm0tursc5uu6yM8WEsf
5TCQtSgGoQv3ZvMKZxsxYvuv7BKvvM37aOkgmjdXFteR62lo79j8wPeUdoFrN8Zv
iQrSTvd4cxrJEGxRWz2rfSZOAUM=
-----END CERTIFICATE-----
`
	cert3CertSubj = "CN=oauth2-proxy test cert3 ca"
	cert3Cert     = `-----BEGIN CERTIFICATE-----
MIIEwDCCAqgCAQEwDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwab2F1dGgyLXBy
b3h5IHRlc3Qgcm9vdDMgY2EwIBcNMjIwNzA3MjMyNzUzWhgPMzAyMTExMDcyMzI3
NTNaMCUxIzAhBgNVBAMMGm9hdXRoMi1wcm94eSB0ZXN0IGNlcnQzIGNhMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3eyZDmSxuGDhSvzU0k3VxZDI9c+X
ruVRjXwj/bA5K4OJa56GG7U2Md1VNog3t2CtJK4eMHMPl9t8wKj4ECs+IgL54o+o
Vf/RTV1o/PUNYhKmQhuprPFEGYkpwJzZy9f9cgB16Lr4wuUhD/LzzzJwftn7orBM
h6GooNtnxCYcmJVtFI73uwBT70cXEV+ziDyfutPIxSOC7XtcDzl5ZocapzezqTjN
xFczC3r1bRDOEGa/B8yLaH1FqtH92+cZguwdhEq8TxZE+V1Ze/jqOfodFSpcpcz4
8A2BIjNU2gDjsnWOKlI5NxS7UbTHqXX65GsYPR5jfsaEkGf1B5aqXXuElW2iW+cA
YzSz2K2yI1VNAy1Vpw+P0PhvEjZyKFPihMn1KEkE3RRRbqaXI50csruUhqdH3mOO
8sfLW5c4CsHB1FmLp3hD0S6yeOVb+QIQLNwVwcHsnhNKbz6h+J20yg5KYdN6pt/X
45eDl/RTsw4utpHllQrq9m++KmZhiDWEtjnSTR4dAtKjW9AFvt/ntytG6hbxlnZb
9dXLvE9FFqKSq4QGWc2YL+n+5iWSFk2ZqbMRPUsJ0eHukGkM0JMG7cwapnWuUKtx
USxGbcW2k+DfgmlWhOfMHQszSWA9A1zFItf56s3i3OqpBd6YsBAK0W2tq19ZlgTR
zWcDqKMep3TrDLkCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEApdjE/eHCFOtBxvyk
hNtjnXPwkTxesPbK1GwqhdDRA+k8xTFHML/zSS4OwYlxZBGCeBrFmxsN3mOvNnJc
iNWaqjnKWA+Bec2oTXo7LX+i1YWHh0cJpPrSmMeVoqX1rsiugOzR3FtAawMN+b+Z
UIC3q0zxZebB074xQxPcMtX7N288VWpFaITLcZftmSQ9w16qAuixVfTYbHQbcE2Q
hCR2lNlNaGX5N9RaDD+MonB1iSJMFL8G9lhGHLPcjJwjkSHpcGp+yplbMRlsUqww
ysfSIPMKydlLJUoVfhl1CnZmFE4NidxSF+wV0M3ai9CFGZ34HcXx28Jj8rFjnibN
AFgjUfC7DvXLb3INJYHi9ZVTXZlliElF5evKhk9NzNXk1gdam+7uFvqPKSYGecX/
fDcov2LkS95u4Zd692xaiE6UUxT4qcKEoZ5TM0aGjJjx0fDAYqgXes5lA3AYIN0S
hAEEC1diGFkQivnBjfxKMkauStsV828yTxtqOdlu75sUcW58AUKJ0LZ6bf8gzVSf
iY7GK6JBDUyme+kio9EutSx5WrTylPzCek9ajNoEUvlmBX8Dz+qG66vFfcff+bo2
Ixm/I9aL4lNQiCmE5E044L00IX802hE9iSdYqFbUmefKqk9NWK3CPtDoobcFLi6u
WrW4JMzLaGDtoHxRNNfo8E7fGkQ=
-----END CERTIFICATE-----
`
)

func makeTestCertFile(t *testing.T, pem, dir string) *os.File {
	file, err := os.CreateTemp(dir, "test-certfile")
	assert.NoError(t, err)
	_, err = file.Write([]byte(pem))
	assert.NoError(t, err)
	return file
}

func TestGetCertPool_NoRoots(t *testing.T) {
	_, err := GetCertPool([]string(nil), false)
	assert.Error(t, err, "invalid empty list of Root CAs file paths")
}

func TestGetCertPool(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "certtest")
	assert.NoError(t, err)
	defer func(path string) {
		rerr := os.RemoveAll(path)
		if rerr != nil {
			panic(rerr)
		}
	}(tempDir)

	rootPool, _ := x509.SystemCertPool()
	cleanPool := x509.NewCertPool()

	tests := []struct {
		appendCerts bool
		pool        *x509.CertPool
	}{
		{false, cleanPool},
		{true, rootPool},
	}

	certFile1 := makeTestCertFile(t, root1Cert, tempDir)
	certFile2 := makeTestCertFile(t, root2Cert, tempDir)

	for _, tc := range tests {
		// Append certs to "known" pool so we can compare them
		assert.True(t, tc.pool.AppendCertsFromPEM([]byte(root1Cert)))
		assert.True(t, tc.pool.AppendCertsFromPEM([]byte(root2Cert)))

		certPool, err := GetCertPool([]string{certFile1.Name(), certFile2.Name()}, tc.appendCerts)
		assert.NoError(t, err)
		assert.True(t, tc.pool.Equal(certPool))

		cert1Block, _ := pem.Decode([]byte(cert1Cert))
		cert1, _ := x509.ParseCertificate(cert1Block.Bytes)
		assert.Equal(t, cert1.Subject.String(), cert1CertSubj)

		cert2Block, _ := pem.Decode([]byte(cert2Cert))
		cert2, _ := x509.ParseCertificate(cert2Block.Bytes)
		assert.Equal(t, cert2.Subject.String(), cert2CertSubj)

		cert3Block, _ := pem.Decode([]byte(cert3Cert))
		cert3, _ := x509.ParseCertificate(cert3Block.Bytes)
		assert.Equal(t, cert3.Subject.String(), cert3CertSubj)

		opts := x509.VerifyOptions{
			Roots: certPool,
		}

		// "cert1" and "cert2" should be valid because "root1" and "root2" are in the certPool
		// "cert3" should not be valid because "root3" is not in the certPool
		_, err1 := cert1.Verify(opts)
		assert.NoError(t, err1)
		_, err2 := cert2.Verify(opts)
		assert.NoError(t, err2)
		_, err3 := cert3.Verify(opts)
		assert.Error(t, err3)
	}
}
