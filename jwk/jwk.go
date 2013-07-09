package jwk

import (
  "crypto/x509"
  "crypto/rsa"
  "encoding/pem"
  "encoding/base64"
  "encoding/binary"
  "strings"
  "fmt"
  "math/big"
)

// A JWK Key Object is a JSON object containing specific members
// that are common to all key types.
//
// Example:
//
//  {
//   "algorithm": "RSA",
//   "modulus": "ALmSsduEhuTIQ6MuQWqahVOzB34wGUyI44bfHY+eP2z9CVmK3xEILHTNl/AqUxzvqld+d9R1vjCrsR+XhLbPZMxPpQRHbOWloaAiwrsrF4xO9DG2amHEEQBkDLNmF9bUvmdcC2ic3fjhYIsQXS9Wc8Npct7mRO6qU2PmCwDF2xmj",
//   "exponent": "AQAB",
//   "keyid": "e1c7a3cddaf3719ae0cede3928ffed250af2d283"
//  },
type Key struct {
  Algorithm string    `json:"algorithm"` // the algorithm used with the key
  Use       string    `json:"use,omitempty"`       // intended use of the key
  KeyId     string    `json:"keyid"`     // use to match a specific key
}

// JWK Key Object Members for RSA Keys
// the algorithm member value MUST be RSA. Furthermore, these additional members MUST be present:
type RSAKey struct {
  Algorithm string    `json:"algorithm"` // the algorithm used with the key
  Use       string    `json:"use,omitempty"`       // intended use of the key
  Modulus   string    `json:"modulus"`
  Exponent  string    `json:"exponent"`
  KeyId     string    `json:"keyid"`     // use to match a specific key
}

type RSAKeySet struct {
  KeyValues []*RSAKey      `json:"keyvalues"`
}

// base64Encode returns and Base64url encoded version of the input string with any
// trailing "=" stripped.
func base64Encode(b []byte) string {
  return strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=")
}

func ParseCertificate(publicKeyPemBytes []byte) (*rsa.PublicKey, error) {
  block, _ := pem.Decode([]byte(publicKeyPemBytes))

  c, err := x509.ParseCertificate(block.Bytes)
  if (err != nil) {
    return nil, err 
  }

  key, ok := c.PublicKey.(*rsa.PublicKey)
  if !ok {
    return nil, fmt.Errorf("Parsed key was not a RSA key")
  }
  return key, nil
} 

func encodeExponent(v int) string {
  b := make([]byte, 4)
  binary.BigEndian.PutUint32(b, uint32(v))
  for i := range b {
    if b[i] != 0 {
      b = b[i:]
      break
    }
  }
  return base64Encode(b)
}

func encodeModulus(v *big.Int) string {
  b := (*v).Bytes() 

  // The private key values are encoded as ASN.1 INTEGERs, which are signed 
  // values in two's complement format. The leading zero byte is necessary when 
  // the MSB of the (unsigned) RSA key value is set. Having the MSB set without 
  // a leading zero byte would mean a negative value.
  if b[0] != 0 {
    b = append([]byte{0}, b...)  
  }
  return base64Encode(b)
}

func NewRSAKey(keyid string, publicKeyPemBytes string) (*RSAKey, error) {
  pub, err := ParseCertificate([]byte(publicKeyPemBytes))
  if (err != nil) {
    return nil, err 
  }

  k := &RSAKey {
    Algorithm: "RSA",
    Use: "", 
    Modulus: encodeModulus(pub.N),
    KeyId: keyid,
    Exponent: encodeExponent(pub.E),
  }
  return k, nil
}



