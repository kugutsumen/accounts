package identity

import (
  "appengine"
  "encoding/json"
  "jwk"
  pb "appengine_internal/app_identity"
)

func GetPublicCertificates(c appengine.Context) ([]*pb.PublicCertificate, error) {
  req := &pb.GetPublicCertificateForAppRequest{}
  res := &pb.GetPublicCertificateForAppResponse{}

  err := c.Call("app_identity_service", "GetPublicCertificatesForApp", req, res, nil)
  if err != nil {
    return nil, err
  }
  return res.GetPublicCertificateList(), err
}

func GetPublicCertificatesJSON(c appengine.Context) ([]byte, error) {
  certs, err := GetPublicCertificates(c)
  if (err != nil) {
    return nil, err
  } else {
    m := make(map[string]string)
    for _, c := range certs {
      if block := c.GetX509CertificatePem(); block != "" {
        m[c.GetKeyName()] = block
      }
    }
    b, err := json.MarshalIndent(m, "", " ")
    if (err != nil) {
      return nil, err
    }
    return b, nil
  }
}
// func GetJWK(c appengine.Context) ([]byte, error) {
func GetJWKSet(c appengine.Context) ([]byte, error) {
  certs, err := GetPublicCertificates(c)
  if (err != nil) {
    return nil, err
  } else {
    ks := make([]*jwk.RSAKey, len(certs))
    for i, c := range certs {
      k, err := jwk.NewRSAKey(c.GetKeyName(), c.GetX509CertificatePem()) 
      ks[i] = k
      if (err != nil) {
        return nil, err
      }
    }
    jwkset := jwk.RSAKeySet{ KeyValues: ks }
    b, err := json.MarshalIndent(jwkset, "", " ")
    if (err != nil) {
      return nil, err
    }
    return b, nil
  }
}

