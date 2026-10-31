package nodepki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"
)

func identityRootSet(directory string, anchor []byte, now time.Time) (*RootSet, error) {
	if directory == "" {
		return nil, nil
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrRootRotation
	}
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil, nil
	}
	roots, _, err := readRootSet(directory, anchor, now, true)
	return roots, err
}

// TLS handshakes validate chain and hostname with the currently authorized
// issuers. Per-RPC FileTrust verification independently enforces live CRLs;
// expired authentic CRLs never authorize ordinary collection or renewal.
func RootPoolFromState(caFile, directory string, now time.Time) (*x509.CertPool, error) {
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return nil, ErrIdentity
	}
	roots, err := identityRootSet(directory, anchor, now)
	if err != nil {
		return nil, err
	}
	if roots != nil {
		return roots.Pool(), nil
	}
	ca, err := parseCertificate(anchor)
	if err != nil || !validAuthority(ca, now) {
		return nil, ErrIdentity
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, nil
}

func identityPairWithRootState(raw, anchor []byte, directory, role, id string, now time.Time, allowExpired bool) (*tls.Certificate, IdentityRecord, []byte, error) {
	roots, err := identityRootSet(directory, anchor, now)
	if err != nil {
		return nil, IdentityRecord{}, nil, err
	}
	return identityPairForRoots(raw, anchor, roots, role, id, now, allowExpired)
}

func identityPairForRoots(raw, anchor []byte, roots *RootSet, role, id string, now time.Time, allowExpired bool) (*tls.Certificate, IdentityRecord, []byte, error) {
	issuer := anchor
	if roots != nil {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, IdentityRecord{}, nil, ErrIdentity
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, IdentityRecord{}, nil, ErrIdentity
		}
		issuer = nil
		for _, root := range roots.roots {
			if cert.CheckSignatureFrom(root) == nil {
				issuer = certificatePEM(root)
				break
			}
		}
		if len(issuer) == 0 {
			return nil, IdentityRecord{}, nil, ErrIdentity
		}
	}
	pair, record, err := identityPair(raw, issuer, role, id, now, allowExpired)
	return pair, record, issuer, err
}

func ReadIdentityWithRootState(caFile, file, directory, role, id string, now time.Time) (Bundle, IdentityRecord, error) {
	return readIdentityWithRootState(caFile, file, directory, role, id, now, false)
}

// Inspect an expired predecessor only for an exact already-issued root
// activation receipt. It never authorizes a fresh CSR, issuance, TLS or
// ordinary renewal. Revocation and the current successor validity still apply.
func ReadRootActivationIdentity(caFile, file, directory, role, id string, snapshot RootSetSnapshot, request RootIdentityRequest, certificate []byte, now time.Time) (Bundle, IdentityRecord, error) {
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil || request.Role != role || request.ID != id || ValidateRootIdentityCertificate(anchor, snapshot, request, certificate, now) != nil {
		return Bundle{}, IdentityRecord{}, ErrRootRotation
	}
	b, record, err := readIdentityWithRootState(caFile, file, directory, role, id, now, true)
	if err != nil {
		return b, record, err
	}
	if bytes.Equal(b.Certificate, request.Certificate) || bytes.Equal(b.Certificate, certificate) {
		return b, record, nil
	}
	clear(b.Key)
	return Bundle{}, IdentityRecord{}, ErrRootRotation
}

func readIdentityWithRootState(caFile, file, directory, role, id string, now time.Time, allowExpired bool) (Bundle, IdentityRecord, error) {
	if directory == "" {
		return readIdentity(caFile, file, role, id, now, allowExpired)
	}
	var b Bundle
	if !filepath.IsAbs(file) || filepath.Clean(file) != file || secureDirectory(filepath.Dir(file)) != nil {
		return b, IdentityRecord{}, ErrIdentity
	}
	anchor, err := readTrustFile(caFile, 64<<10)
	if err != nil {
		return b, IdentityRecord{}, ErrIdentity
	}
	raw, err := readIdentityFile(file, MaxIdentityBytes, true)
	if err != nil {
		return b, IdentityRecord{}, ErrIdentity
	}
	defer clear(raw)
	_, record, issuer, err := identityPairWithRootState(raw, anchor, directory, role, id, now, allowExpired)
	if err != nil {
		return b, IdentityRecord{}, err
	}
	cert, rest := pem.Decode(raw)
	key, _ := pem.Decode(rest)
	b.CA, b.Certificate, b.Key = issuer, pem.EncodeToMemory(cert), pem.EncodeToMemory(key)
	return b, record, nil
}
