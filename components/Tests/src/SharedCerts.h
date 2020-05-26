/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#define TEST_ROOT_CA_CERT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDkDCCAnegAwIBAgIUXEphp/RzjJH6jYvDDsBQdrGYRSowDQYJKoZIhvcNAQEL\r\n" \
    "BQAwVzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\r\n" \
    "GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEQMA4GA1UEAwwHQ0EgQ0VSVDAeFw0y\r\n" \
    "MDA1MTQxNTM2MjdaFw0yNTA1MTQxNTM2MjdaMFcxCzAJBgNVBAYTAkFVMRMwEQYD\r\n" \
    "VQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBM\r\n" \
    "dGQxEDAOBgNVBAMMB0NBIENFUlQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\r\n" \
    "AoIBAQGcLALOFvMkMTxljth3mkcgrPSgyA/9zFzaTidCEhyqUcz6voXsOaEisodD\r\n" \
    "UU1Y41uJ/jvVhSsuecdZZ6oADDEmRGXXUKX4ZXiK2wFGkUykLrO8Y1hpES3cPHVt\r\n" \
    "1NzJXSYydGp/pnGTgKHfWiwvMdu7E6g2nSkwlFcPFuFTAWPDkZcwfKd84AJCQbyT\r\n" \
    "04qZ2V7u1AzGTdgQ70XtCLzlFj+pEwxCCKvZRt3JeCPHWUOZ65TXGwMFCf72ku2J\r\n" \
    "eAN/SHCKL7Ogm+w+bV8hTTFshzTiwpc7+olb/VzgAX/pLggtMVxIlLOeggy1C/d3\r\n" \
    "Ro3qfAWlQKRoiqm1KJIF+d/OmlBpAgMBAAGjUzBRMB0GA1UdDgQWBBQ0flvr/vJ0\r\n" \
    "bMGSCWRX7aht51p5FTAfBgNVHSMEGDAWgBQ0flvr/vJ0bMGSCWRX7aht51p5FTAP\r\n" \
    "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAgABMfXm0dT19YmOxmLE\r\n" \
    "SjSYFZ9UTV12T/aO+RBK3Unb92DZGtj//UoIN/qE3bxt96XKixATp0WNQxilB6Pl\r\n" \
    "kSQ+AB2ucwzYsGZiJIkfCiCkyqFHUVIZ7FhYOlDyaDwNYQhl6PbBIBEwMTvPAgAg\r\n" \
    "pLiroF3rpg9PIi0vzYPPzaTe+PYudcYk0t8iqwWqSKz4RE0j2omyO7ljM8HPgoz+\r\n" \
    "2ArbFTKjFvAtw50vZFT0nH/cTtMf1VTlTy0kkGQacoGhAOVj+hq+ucAaP43ArJqH\r\n" \
    "1oHJU/rq1kJljRXXZRO695Uk46IhPNDhAu1L0ml6ansEz9Fl28Yal0Z2+zL0rUAz\r\n" \
    "gqZivg==\r\n" \
    "-----END CERTIFICATE-----\r\n"

#define TEST_IMED_CA_CERT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDNzCCAh4CFHbRcbAo6lHOaFjcHj8WsC4A0W+wMA0GCSqGSIb3DQEBCwUAMFcx\r\n" \
    "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\r\n" \
    "cm5ldCBXaWRnaXRzIFB0eSBMdGQxEDAOBgNVBAMMB0NBIENFUlQwHhcNMjAwNTE0\r\n" \
    "MTUzODMwWhcNMjMwMjA4MTUzODMwWjBYMQswCQYDVQQGEwJBVTETMBEGA1UECAwK\r\n" \
    "U29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMREw\r\n" \
    "DwYDVQQDDAhJTlQgQ0VSVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" \
    "AJMA/t/8IG5oebEzbHd8lsEWO2K0gzc27Qzv9cZ6mDEHQsxrJYIKmWF9I3++JbKF\r\n" \
    "8a7mz7ffsUvzgHN0u36aqgzDRTad1Mp9zaSoPeVYBdQbxUfAIWa2OvFIwiHPYmEL\r\n" \
    "hYKnY6eEpbst2HLlSAlRamDIQQVASaLJZ+6HF6sJOSs0I5T5AhOAfZ7sbtg0V4HI\r\n" \
    "9j20PB/DQFf6HsX9eDyEfpqUC3GDrKMmuIXaFK6afQSIvKsGqOaQAW7mmG2ceFKB\r\n" \
    "Uxl6gnFW5sXBiAny10uOOhLaTj/+MkPqh3cjXY4TrQlQXh01TBoXVOON9pUor1tw\r\n" \
    "Z6XE0J2GZWioEjIq+NPVQu8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQIAANTpRW4A\r\n" \
    "CC+daGf5ubJRVFRB3NPKxMiTOhtBh1Lphi3A9OrTS7BcdU1NrfnGOfhI4DPxfaO2\r\n" \
    "3yO9DEDLorUlu3+qibhDNa6Gb923BJ12Ds26A/yngA5cOm9/CH7ZVxEq3dsg0kxD\r\n" \
    "eG4ansAXIVsLE0u5olMJPSkZvpcIvGwWMBqhJhb/DHs3eXxMvzz4B3CYLR6qdA3q\r\n" \
    "VUSV6WAjlSmWCF7HXP4Sc++QBRl66FrMGDH20RZse61tq6xo12VHhyZeH5j2JZzl\r\n" \
    "p7KAL9QH/TF7cq73sRSGnRiHlIO+j5jUG25Hcb8IQgSzZ64tF56iGyNhLeieLHTt\r\n" \
    "Ht77hK6Ffknm4lY=\r\n" \
    "-----END CERTIFICATE-----\r\n"

#define TEST_SERVER_CERT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDJzCCAg8CAWUwDQYJKoZIhvcNAQELBQAwWDELMAkGA1UEBhMCQVUxEzARBgNV\r\n" \
    "BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\r\n" \
    "ZDERMA8GA1UEAwwISU5UIENFUlQwHhcNMjAwNTE0MTYyOTUwWhcNMjMwMjA4MTYy\r\n" \
    "OTUwWjBbMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\r\n" \
    "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRQwEgYDVQQDDAtTRVJWRVIgQ0VS\r\n" \
    "VDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALN2lyc/c42I8FBiNU4E\r\n" \
    "pt8er6qAZ19U7eoAV3usmMNa7eyzwRgowWY/UBFoaeW1aOSrzU6ukglUk8a2y85M\r\n" \
    "rDaL4cJHvdb6I37aw1rUITi7DrUUPp/wXzY6HnDbiWO5JM585OABc3YMvr7LUdXF\r\n" \
    "Ba4Kr8qyIHTi+tELyCGgrE/XalPxCmiBZ6pXJZvHq3w2faq+R/LgPRnorDaelChO\r\n" \
    "70G2NVk+aoXqf2VG18VL2b7eB02GaUvNIgEkqU4R1wKGjpUq9owbT4aMDyGXXzSv\r\n" \
    "PaHPEcbBdpH9CJg4No8gtISKo0fkbpzaIs9/dO9o0Ga2wiqjO9KjrEoe8neO/LrN\r\n" \
    "8T8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAEwN6cMNA4MOx/j+399Teb36PmauZ\r\n" \
    "mUDIkrcR95FSdIasTxCK7RpZ6P08RC+7EqP66igXeD88ka3PC8Co58ll+4bIZA77\r\n" \
    "gunKskUNQ1z/RACPKwuUbNSLb+7a4B9bfErPOPa/ckrjFBm9Qu4UahoSV0N6CVpd\r\n" \
    "BSDTDKJObiOzkexXahpeX6UAiU+Z9/MiE9GrqUqB2B9LX9s2G63mbTz9tUQyWp2e\r\n" \
    "r4iuTnKYkHJAV7j5gW8uIlVaasPQbrf0fH511A8oFeeNt6ik1KIUPD9sF+5qG3Yv\r\n" \
    "UHBt9lKNPJ0Zz1AaYGW0vrE6gHB1Ql+5bNyWnFON5pnvnPBUXA96KPNueA==\r\n" \
    "-----END CERTIFICATE-----\r\n"

typedef struct
{
    const uint8_t* cert;
    size_t len;
} PemData_t;

/*
 * Not everybody who includes this header needs to use all defined variables
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"

static const uint8_t rootCert[]   = TEST_ROOT_CA_CERT;
static const uint8_t imedCert[]   = TEST_IMED_CA_CERT;
static const uint8_t serverCert[] = TEST_SERVER_CERT;

static const PemData_t caChain[] =
{
    { rootCert, sizeof(rootCert) },
    { imedCert, sizeof(imedCert) },
};

#pragma GCC diagnostic pop