package jwk

import (
  "testing"
)

// On App Engine
// key_name:"50db885c9006426cc9376a07d63cb3b43fac57c9" x509_certificate_pem:"-----BEGIN CERTIFICATE-----\nMIICITCCAYqgAwIBAgIIasRsdZoCcWowDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrYmVsbHVhLWFjY291bnRzLmFwcHNwb3QuZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xMzA3MDcxNDUyNDZaFw0xMzA3MDkwMzUyNDZaMDYxNDAyBgNVBAMTK2JlbGx1\nYS1hY2NvdW50cy5hcHBzcG90LmdzZXJ2aWNlYWNjb3VudC5jb20wgZ8wDQYJKoZI\nhvcNAQEBBQADgY0AMIGJAoGBAKv6Qi6F+zghFIBf4wYYLza5/wTjfIup0lq9AD+s\nj6lhQy53JzhF0a4ol8BT12zvlAKNCtyb4JI3A4TMPhPgCXnZ8wQkkFzK6UniJxab\nYXct49TkesXAWcSAt8ShDKsBO3lizuS83yIUkoOLJAh92zrCueVg5elahDiPe3//\nDliLAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1Ud\nJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4GBAFlcuCrXE1EH1pAK\nBObbBlqQmdahk7lLQhXCpTBqQzhs2qoZ1TsptuTFdtDjGdJ7ULqZyduliqCxElb8\npn7AO+grZ8w8yRGR6c5A4CcwoAzSYUherZQg02prg53imRflGaai/wjldiG6uGuf\nwwB7PqRFesVi/ws6YcfXH5UXbLHE\n-----END CERTIFICATE-----\n"

// On Dev Server:
//

// https://www.googleapis.com/oauth2/v1/certs
const keyid = "e1c7a3cddaf3719ae0cede3928ffed250af2d283"
const algorithm = "RSA"
const exponentBase64 = "AQAB"
const exponent = 65537
const modulusBase64 = "ALmSsduEhuTIQ6MuQWqahVOzB34wGUyI44bfHY+eP2z9CVmK3xEILHTNl/AqUxzvqld+d9R1vjCrsR+XhLbPZMxPpQRHbOWloaAiwrsrF4xO9DG2amHEEQBkDLNmF9bUvmdcC2ic3fjhYIsQXS9Wc8Npct7mRO6qU2PmCwDF2xmj"

const publicKeyPemBytes = `
-----BEGIN CERTIFICATE-----
MIICITCCAYqgAwIBAgIIWor2HcdfOsgwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE
AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe
Fw0xMzA3MDYyMDI4MzRaFw0xMzA3MDgwOTI4MzRaMDYxNDAyBgNVBAMTK2ZlZGVy
YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBALmSsduEhuTIQ6MuQWqahVOzB34wGUyI44bfHY+e
P2z9CVmK3xEILHTNl/AqUxzvqld+d9R1vjCrsR+XhLbPZMxPpQRHbOWloaAiwrsr
F4xO9DG2amHEEQBkDLNmF9bUvmdcC2ic3fjhYIsQXS9Wc8Npct7mRO6qU2PmCwDF
2xmjAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1Ud
JQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4GBAGVHHxP8e/fSyDlO
FWKjnjrbUjC4nAVwipeW7rfD5Gi8uXm0x+cle4a5aIlLgTdDRzjdsuEdz3/HsfDR
u/ctT1/TUYEMI7ubl5R8xMDu5heMJuYFUyfPppdNsEB8qSEfMs9lBphIV3fUF533
5Mg0LN18nHck4hc9LsWGCRyuCPN3
-----END CERTIFICATE-----
`


const certs = `
{
 "e1c7a3cddaf3719ae0cede3928ffed250af2d283": "-----BEGIN CERTIFICATE-----\nMIICITCCAYqgAwIBAgIIWor2HcdfOsgwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0xMzA3MDYyMDI4MzRaFw0xMzA3MDgwOTI4MzRaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wgZ8wDQYJKoZI\nhvcNAQEBBQADgY0AMIGJAoGBALmSsduEhuTIQ6MuQWqahVOzB34wGUyI44bfHY+e\nP2z9CVmK3xEILHTNl/AqUxzvqld+d9R1vjCrsR+XhLbPZMxPpQRHbOWloaAiwrsr\nF4xO9DG2amHEEQBkDLNmF9bUvmdcC2ic3fjhYIsQXS9Wc8Npct7mRO6qU2PmCwDF\n2xmjAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1Ud\nJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4GBAGVHHxP8e/fSyDlO\nFWKjnjrbUjC4nAVwipeW7rfD5Gi8uXm0x+cle4a5aIlLgTdDRzjdsuEdz3/HsfDR\nu/ctT1/TUYEMI7ubl5R8xMDu5heMJuYFUyfPppdNsEB8qSEfMs9lBphIV3fUF533\n5Mg0LN18nHck4hc9LsWGCRyuCPN3\n-----END CERTIFICATE-----\n",
 "94cf5b95ca2a78f9fde46da040bc30d703d41dd1": "-----BEGIN CERTIFICATE-----\nMIICIDCCAYmgAwIBAgIHY2QVFANnSDANBgkqhkiG9w0BAQUFADA2MTQwMgYDVQQD\nEytmZWRlcmF0ZWQtc2lnbm9uLnN5c3RlbS5nc2VydmljZWFjY291bnQuY29tMB4X\nDTEzMDcwNzIwMTMzNFoXDTEzMDcwOTA5MTMzNFowNjE0MDIGA1UEAxMrZmVkZXJh\ndGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCBnzANBgkqhkiG\n9w0BAQEFAAOBjQAwgYkCgYEAsEs4Fj65t1WsvhNpGzzXDuiLocMLE7b+vldV0xeW\njMVmLr1HkJEwXQsEQ5NWS2nqOkHrsXrXHr7CdXfGimP9Z+onxNgEDYHt5TnJULyw\nEjHkIt/JAbTD4JhXNHt0u8q7CHAwibyDZMwcfgpfiE+8dmkqx5cmKDBLPfZSiY3k\n3EsCAwEAAaM4MDYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l\nAQH/BAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQEFBQADgYEARyd+6+A7L5nRIijZ\nP25c8Y7BykazmpwlL6PqxFE4BpScMpFzJtc1enfSqj/HuZUuIRsZMSWDYhum3hRD\nzGLV/x1QQAuc3zGrPmQBHetdNDFojlWT3pQtU4RHJUUnlQPG5bg8VZ7uwiwiCdzu\n9TkSUIy2qFPCc4fAwQhjRl8KcuM=\n-----END CERTIFICATE-----\n"
}`


// https://www.googleapis.com/service_accounts/v1/metadata/raw/federated-signon@system.gserviceaccount.com
const jwk_certs = `
{
 "keyvalues": [
  {
   "algorithm": "RSA",
   "modulus": "ALmSsduEhuTIQ6MuQWqahVOzB34wGUyI44bfHY+eP2z9CVmK3xEILHTNl/AqUxzvqld+d9R1vjCrsR+XhLbPZMxPpQRHbOWloaAiwrsrF4xO9DG2amHEEQBkDLNmF9bUvmdcC2ic3fjhYIsQXS9Wc8Npct7mRO6qU2PmCwDF2xmj",
   "exponent": "AQAB",
   "keyid": "e1c7a3cddaf3719ae0cede3928ffed250af2d283"
  },
  {
   "algorithm": "RSA",
   "modulus": "ALBLOBY+ubdVrL4TaRs81w7oi6HDCxO2/r5XVdMXlozFZi69R5CRMF0LBEOTVktp6jpB67F61x6+wnV3xopj/WfqJ8TYBA2B7eU5yVC8sBIx5CLfyQG0w+CYVzR7dLvKuwhwMIm8g2TMHH4KX4hPvHZpKseXJigwSz32UomN5NxL",
   "exponent": "AQAB",
   "keyid": "94cf5b95ca2a78f9fde46da040bc30d703d41dd1"
  }
 ]
}`

//    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/MY_CLIENT_ID@developer.gserviceaccount.com",

// https://www.googleapis.com/service_accounts/v1/metadata/raw/bellua-accounts@appspot.gserviceaccount.com


// Given an exponent test for proper encoding
func TestEncodeExponent(t *testing.T) {
  s := encodeExponent(exponent) 
  if s != exponentBase64 {
    t.Error("TestEncodeExponent: encodedExponent != exponentBase64")
    t.Errorf("  encodedExponent = %s", s)
    t.Errorf("      exponentBase64 = %s", exponentBase64)
  }
}

// Given a well formed JWK cert, test for proper encoding
func TestNewRSAKey(t *testing.T) {
  key, err := NewRSAKey(keyid, publicKeyPemBytes)
  if err != nil {
    t.Errorf("TestNewRSAKey: %s", err) 
  }
  if key.KeyId != keyid {
    t.Error("TestNewRSAKey: key.KeyId != keyid")
    t.Errorf("  key.KeyId = %s", key.KeyId)
    t.Errorf("      keyid = %s", keyid)
  }
  if key.Algorithm != algorithm {
    t.Error("TestNewRSAKey: key.Algorithm != algorithm")
    t.Errorf("  key.Algorithm = %s", key.Algorithm)
    t.Errorf("      algorithm = %s", algorithm)
  }
  if key.Exponent != exponentBase64 {
    t.Error("TestNewRSAKey: key.Exponent != exponentBase64")
    t.Errorf("  key.Exponent = %s", key.Exponent)
    t.Errorf("      exponentBase64 = %s", exponentBase64)
  }
  if key.Modulus != modulusBase64 {
    t.Error("TestNewRSAKey: key.Modulus != modulusBase64")
    t.Errorf("  key.Modulus = %s", key.Modulus)
    t.Errorf("      modulusBase64 = %s", modulusBase64)
  }
}

