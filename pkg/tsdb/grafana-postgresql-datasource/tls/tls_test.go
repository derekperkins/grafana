package tls

import (
	"errors"
	"testing"

	"github.com/grafana/grafana/pkg/tsdb/sqleng"
	"github.com/stretchr/testify/require"
)

func mockReadFile(path string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func TestTLSNoMode(t *testing.T) {
	// for backward-compatibility reason,
	// when mode is unset, it defaults to `require`
	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			ConfigurationMethod: "",
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, c.InsecureSkipVerify)
}

func TestTLSDisable(t *testing.T) {
	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "disable",
			ConfigurationMethod: "",
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.Nil(t, c)
}

func TestTLSRequire(t *testing.T) {
	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "require",
			ConfigurationMethod: "",
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, c.InsecureSkipVerify)
}

func TestTLSRequireWithRootCert(t *testing.T) {
	rootCertBytes, err := CreateRandomRootCertBytes()
	require.NoError(t, err)

	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "require",
			ConfigurationMethod: "file-content",
		},
		DecryptedSecureJSONData: map[string]string{
			"tlsCACert": string(rootCertBytes),
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, c.InsecureSkipVerify)
	require.NotNil(t, c.VerifyConnection)
	// TODO: somehow verify that the root certificate was added.
	// unfortunately there is no way to look "inside" an x509.CertPool
}

func TestTLSVerifyCA(t *testing.T) {
	rootCertBytes, err := CreateRandomRootCertBytes()
	require.NoError(t, err)

	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "verify-ca",
			ConfigurationMethod: "file-content",
		},
		DecryptedSecureJSONData: map[string]string{
			"tlsCACert": string(rootCertBytes),
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, c.InsecureSkipVerify)
	require.NotNil(t, c.VerifyConnection)
	// TODO: somehow verify that the root certificate was added.
	// unfortunately there is no way to look "inside" an x509.CertPool
}

func TestTLSVerifyCAMisingRootCert(t *testing.T) {
	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "verify-ca",
			ConfigurationMethod: "file-content",
		},
		DecryptedSecureJSONData: map[string]string{},
	}
	_, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.ErrorIs(t, err, errNoRootCert)
}

func TestTLSClientCert(t *testing.T) {
	clientKey, clientCert, err := CreateRandomClientCert()
	require.NoError(t, err)

	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "require",
			ConfigurationMethod: "file-content",
		},
		DecryptedSecureJSONData: map[string]string{
			"tlsClientCert": string(clientCert),
			"tlsClientKey":  string(clientKey),
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, c.InsecureSkipVerify)
}

func TestTLSVerifyFull(t *testing.T) {
	rootCertBytes, err := CreateRandomRootCertBytes()
	require.NoError(t, err)

	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "verify-full",
			ConfigurationMethod: "file-content",
		},
		DecryptedSecureJSONData: map[string]string{
			"tlsCACert": string(rootCertBytes),
		},
	}
	c, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.False(t, c.InsecureSkipVerify)
	require.Nil(t, c.VerifyConnection)
	// TODO: somehow verify that the root certificate was added.
	// unfortunately there is no way to look "inside" an x509.CertPool
}

func TestTLSVerifyFullMisingRootCert(t *testing.T) {
	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode:                "verify-full",
			ConfigurationMethod: "file-content",
		},
		DecryptedSecureJSONData: map[string]string{},
	}
	_, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.ErrorIs(t, err, errNoRootCert)
}

func TestTLSInvalidMode(t *testing.T) {
	dsInfo := sqleng.DataSourceInfo{
		JsonData: sqleng.JsonData{
			Mode: "not-a-valid-mode",
		},
	}

	_, err := GetTLSConfig(dsInfo, mockReadFile, "localhost")
	require.Error(t, err)
}
