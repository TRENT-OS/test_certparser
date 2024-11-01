/**
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
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

// Some server key with SHA256 hash, signed by INTERMEDIATE cert
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

// Same key/hash as above, only signed by ROOT cert
#define TEST_SERVER_CERT_ROOT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDJzCCAg4CAWUwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCQVUxEzARBgNV\r\n" \
    "BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\r\n" \
    "ZDEQMA4GA1UEAwwHQ0EgQ0VSVDAeFw0yMDA1MjYxNTAzMDNaFw0yMzAyMjAxNTAz\r\n" \
    "MDNaMFsxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK\r\n" \
    "DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFDASBgNVBAMMC1NFUlZFUiBDRVJU\r\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3aXJz9zjYjwUGI1TgSm\r\n" \
    "3x6vqoBnX1Tt6gBXe6yYw1rt7LPBGCjBZj9QEWhp5bVo5KvNTq6SCVSTxrbLzkys\r\n" \
    "Novhwke91vojftrDWtQhOLsOtRQ+n/BfNjoecNuJY7kkznzk4AFzdgy+vstR1cUF\r\n" \
    "rgqvyrIgdOL60QvIIaCsT9dqU/EKaIFnqlclm8erfDZ9qr5H8uA9GeisNp6UKE7v\r\n" \
    "QbY1WT5qhep/ZUbXxUvZvt4HTYZpS80iASSpThHXAoaOlSr2jBtPhowPIZdfNK89\r\n" \
    "oc8RxsF2kf0ImDg2jyC0hIqjR+RunNoiz39072jQZrbCKqM70qOsSh7yd478us3x\r\n" \
    "PwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAgABFHZVzYIBH4HtqZNfIKkqW4zrkQ3l\r\n" \
    "x2l6PtwNTMW3DzGKJeOoMnHqlMRBEZwQjwDwgeiySY1117rcItt6KAmG2jfKWMIf\r\n" \
    "8EOx5uY9KMegpV3y7NhYuVUxaWbXP/S3JG0pU840CB5K9WE2uy4/EJRLz9qJgsLl\r\n" \
    "wv8A6QGBblNZRTM5B6XFegloWMMH/WvMJr4cLK2eRJ8dbw3IsaHdRrgNlbHq3Fxh\r\n" \
    "24Q8UAv4L2I1vySjeulMvxykk27k7iZf388n9ZalrgpK3ipR4HGQem4YgPRTh/pg\r\n" \
    "oPYyGbCkHMFu9g+LGRYGUJO6V0pCemiQmFyKuOQUbwAVTDTnOVwr6Hevmg==\r\n" \
    "-----END CERTIFICATE-----\r\n"

// Same key as above, signed by ROOT cert but with SHA1 as hash
#define TEST_SERVER_CERT_SHA1 \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDJzCCAg4CAWUwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQVUxEzARBgNV\r\n" \
    "BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\r\n" \
    "ZDEQMA4GA1UEAwwHQ0EgQ0VSVDAeFw0yMDA1MjYxNTEzMTFaFw0yMzAyMjAxNTEz\r\n" \
    "MTFaMFsxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK\r\n" \
    "DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFDASBgNVBAMMC1NFUlZFUiBDRVJU\r\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3aXJz9zjYjwUGI1TgSm\r\n" \
    "3x6vqoBnX1Tt6gBXe6yYw1rt7LPBGCjBZj9QEWhp5bVo5KvNTq6SCVSTxrbLzkys\r\n" \
    "Novhwke91vojftrDWtQhOLsOtRQ+n/BfNjoecNuJY7kkznzk4AFzdgy+vstR1cUF\r\n" \
    "rgqvyrIgdOL60QvIIaCsT9dqU/EKaIFnqlclm8erfDZ9qr5H8uA9GeisNp6UKE7v\r\n" \
    "QbY1WT5qhep/ZUbXxUvZvt4HTYZpS80iASSpThHXAoaOlSr2jBtPhowPIZdfNK89\r\n" \
    "oc8RxsF2kf0ImDg2jyC0hIqjR+RunNoiz39072jQZrbCKqM70qOsSh7yd478us3x\r\n" \
    "PwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAgAApwxTaM5O5f/qatwhkrbu9vpeHKqo\r\n" \
    "/5/2jiP/Ejyk51A8+S8U2qBHasrdCRpIRiF6WFvjA1OCNkASOpMTICn3g4pIYAkE\r\n" \
    "BxeW11QbLsKEoNFDGzc+3MgJ1Ib/fhL6/Qjc3VbKdmrljRbZPqGYwzVj2dLwgJIn\r\n" \
    "6/HJ6GrJdRDk/TWUf90mL607gqoh3z8GvJxXG5W4XdklW1RJGGb1c5QUGFgMCRqx\r\n" \
    "VjfqbCjnh1QUB4TZ7/viDhsVL+WQqr6RU5Lv4rtYE+BMyWVmP2DIwaTywISf5xJt\r\n" \
    "rpqQbWdgky1lQv4jUibqXq4PMANyztVdu6rv4toXvTWSdti9L/wHZzOQ3w==\r\n" \
    "-----END CERTIFICATE-----\r\n"

// ECC 256-bit key, self-signed with SHA256
#define TEST_SERVER_CERT_ECC \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIICEzCCAbmgAwIBAgIUBk0O7KUqQF6pFCAGUH0XkMgn8IEwCgYIKoZIzj0EAwIw\r\n" \
    "XzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\r\n" \
    "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEYMBYGA1UEAwwPRUNDIFNFUlZFUiBDRVJU\r\n" \
    "MB4XDTIwMDUyNjE2NTU0OFoXDTIzMDIyMDE2NTU0OFowXzELMAkGA1UEBhMCQVUx\r\n" \
    "EzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMg\r\n" \
    "UHR5IEx0ZDEYMBYGA1UEAwwPRUNDIFNFUlZFUiBDRVJUMFkwEwYHKoZIzj0CAQYI\r\n" \
    "KoZIzj0DAQcDQgAEqW+IvCyhDBu4vuFQx+JnFb5E7vkE9Sm/fBdr6O+HpyrX2Uce\r\n" \
    "npzsM50RiTRkbT+n65yv77pN479BiFcj4PYb9qNTMFEwHQYDVR0OBBYEFDycTQax\r\n" \
    "cMxxPcJinEQKjj41qOU3MB8GA1UdIwQYMBaAFDycTQaxcMxxPcJinEQKjj41qOU3\r\n" \
    "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKI5kPSJHriI3L5d\r\n" \
    "mVFvgKwqGMM2jfGptGbDquy/RG35AiARzUHpvNfILLzBr8TtoC+tDTAEMqkkfnZq\r\n" \
    "tVodOpXTXg==\r\n" \
    "-----END CERTIFICATE-----\r\n"

// Same key as above, but now self-signed
#define TEST_SERVER_CERT_SELF_SIGNED \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDrzCCApegAwIBAgIUcgaQe5PJduMU4MmnWKCTef9JXU8wDQYJKoZIhvcNAQEL\r\n" \
    "BQAwZzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\r\n" \
    "GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEgMB4GA1UEAwwXU0VMRiBTSUdORUQg\r\n" \
    "U0VSVkVSIENFUlQwHhcNMjAwNTI2MTUzNDAxWhcNMjMwMjIwMTUzNDAxWjBnMQsw\r\n" \
    "CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\r\n" \
    "ZXQgV2lkZ2l0cyBQdHkgTHRkMSAwHgYDVQQDDBdTRUxGIFNJR05FRCBTRVJWRVIg\r\n" \
    "Q0VSVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALN2lyc/c42I8FBi\r\n" \
    "NU4Ept8er6qAZ19U7eoAV3usmMNa7eyzwRgowWY/UBFoaeW1aOSrzU6ukglUk8a2\r\n" \
    "y85MrDaL4cJHvdb6I37aw1rUITi7DrUUPp/wXzY6HnDbiWO5JM585OABc3YMvr7L\r\n" \
    "UdXFBa4Kr8qyIHTi+tELyCGgrE/XalPxCmiBZ6pXJZvHq3w2faq+R/LgPRnorDae\r\n" \
    "lChO70G2NVk+aoXqf2VG18VL2b7eB02GaUvNIgEkqU4R1wKGjpUq9owbT4aMDyGX\r\n" \
    "XzSvPaHPEcbBdpH9CJg4No8gtISKo0fkbpzaIs9/dO9o0Ga2wiqjO9KjrEoe8neO\r\n" \
    "/LrN8T8CAwEAAaNTMFEwHQYDVR0OBBYEFCsFPOHPRY1IDIKLi96797Td9YBuMB8G\r\n" \
    "A1UdIwQYMBaAFCsFPOHPRY1IDIKLi96797Td9YBuMA8GA1UdEwEB/wQFMAMBAf8w\r\n" \
    "DQYJKoZIhvcNAQELBQADggEBAHXXcZuvXE4a2ZRRnnUXsb0q6fvEAbNLljaUUrTa\r\n" \
    "P2r8/1Fe4kvRq+0O2STS2UNVrQ7rSbY+mWfQOk+Tt50deTGuKE7zdx4MhpNqfNVF\r\n" \
    "A1LHYwXghgNmOzoKF8wBD7mpkVRYl+/GpxVHOwyUaeVo9u5HAhff0HobjsCXJcuN\r\n" \
    "dbskQdINBMZklbJy2V752gBon7sTsg2vLYLVlSvILf81JT2ZhkKfqwuY8vUIBoo0\r\n" \
    "QQC0VrzXS/+bAT//8aKyONwYSByngntXdrXXTL+Cq7Jf7Z1Yjx2U9HL+nPNK4oTS\r\n" \
    "/IaG/tBwbf0TMNJ4xVse3+2I97P8xYFKfTrLqGT4W3mhx8g=\r\n" \
    "-----END CERTIFICATE-----\r\n"

// Same as TEST_SERVER_CERT, only in DER encoding
#define TEST_SERVER_CERT_DER \
    { \
        0x30, 0x82, 0x03, 0x27, 0x30, 0x82, 0x02, 0x0f, 0x02, 0x01, 0x65, 0x30, \
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, \
        0x05, 0x00, 0x30, 0x58, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, \
        0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, \
        0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, \
        0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, \
        0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, \
        0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, \
        0x64, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, \
        0x49, 0x4e, 0x54, 0x20, 0x43, 0x45, 0x52, 0x54, 0x30, 0x1e, 0x17, 0x0d, \
        0x32, 0x30, 0x30, 0x35, 0x31, 0x34, 0x31, 0x36, 0x32, 0x39, 0x35, 0x30, \
        0x5a, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x32, 0x30, 0x38, 0x31, 0x36, 0x32, \
        0x39, 0x35, 0x30, 0x5a, 0x30, 0x5b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, \
        0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, \
        0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, \
        0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, \
        0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, \
        0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, \
        0x4c, 0x74, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, \
        0x0c, 0x0b, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x20, 0x43, 0x45, 0x52, \
        0x54, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, \
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, \
        0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb3, 0x76, \
        0x97, 0x27, 0x3f, 0x73, 0x8d, 0x88, 0xf0, 0x50, 0x62, 0x35, 0x4e, 0x04, \
        0xa6, 0xdf, 0x1e, 0xaf, 0xaa, 0x80, 0x67, 0x5f, 0x54, 0xed, 0xea, 0x00, \
        0x57, 0x7b, 0xac, 0x98, 0xc3, 0x5a, 0xed, 0xec, 0xb3, 0xc1, 0x18, 0x28, \
        0xc1, 0x66, 0x3f, 0x50, 0x11, 0x68, 0x69, 0xe5, 0xb5, 0x68, 0xe4, 0xab, \
        0xcd, 0x4e, 0xae, 0x92, 0x09, 0x54, 0x93, 0xc6, 0xb6, 0xcb, 0xce, 0x4c, \
        0xac, 0x36, 0x8b, 0xe1, 0xc2, 0x47, 0xbd, 0xd6, 0xfa, 0x23, 0x7e, 0xda, \
        0xc3, 0x5a, 0xd4, 0x21, 0x38, 0xbb, 0x0e, 0xb5, 0x14, 0x3e, 0x9f, 0xf0, \
        0x5f, 0x36, 0x3a, 0x1e, 0x70, 0xdb, 0x89, 0x63, 0xb9, 0x24, 0xce, 0x7c, \
        0xe4, 0xe0, 0x01, 0x73, 0x76, 0x0c, 0xbe, 0xbe, 0xcb, 0x51, 0xd5, 0xc5, \
        0x05, 0xae, 0x0a, 0xaf, 0xca, 0xb2, 0x20, 0x74, 0xe2, 0xfa, 0xd1, 0x0b, \
        0xc8, 0x21, 0xa0, 0xac, 0x4f, 0xd7, 0x6a, 0x53, 0xf1, 0x0a, 0x68, 0x81, \
        0x67, 0xaa, 0x57, 0x25, 0x9b, 0xc7, 0xab, 0x7c, 0x36, 0x7d, 0xaa, 0xbe, \
        0x47, 0xf2, 0xe0, 0x3d, 0x19, 0xe8, 0xac, 0x36, 0x9e, 0x94, 0x28, 0x4e, \
        0xef, 0x41, 0xb6, 0x35, 0x59, 0x3e, 0x6a, 0x85, 0xea, 0x7f, 0x65, 0x46, \
        0xd7, 0xc5, 0x4b, 0xd9, 0xbe, 0xde, 0x07, 0x4d, 0x86, 0x69, 0x4b, 0xcd, \
        0x22, 0x01, 0x24, 0xa9, 0x4e, 0x11, 0xd7, 0x02, 0x86, 0x8e, 0x95, 0x2a, \
        0xf6, 0x8c, 0x1b, 0x4f, 0x86, 0x8c, 0x0f, 0x21, 0x97, 0x5f, 0x34, 0xaf, \
        0x3d, 0xa1, 0xcf, 0x11, 0xc6, 0xc1, 0x76, 0x91, 0xfd, 0x08, 0x98, 0x38, \
        0x36, 0x8f, 0x20, 0xb4, 0x84, 0x8a, 0xa3, 0x47, 0xe4, 0x6e, 0x9c, 0xda, \
        0x22, 0xcf, 0x7f, 0x74, 0xef, 0x68, 0xd0, 0x66, 0xb6, 0xc2, 0x2a, 0xa3, \
        0x3b, 0xd2, 0xa3, 0xac, 0x4a, 0x1e, 0xf2, 0x77, 0x8e, 0xfc, 0xba, 0xcd, \
        0xf1, 0x3f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, \
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, \
        0x01, 0x01, 0x00, 0x13, 0x03, 0x7a, 0x70, 0xc3, 0x40, 0xe0, 0xc3, 0xb1, \
        0xfe, 0x3f, 0xb7, 0xf7, 0xd4, 0xde, 0x6f, 0x7e, 0x8f, 0x99, 0xab, 0x99, \
        0x99, 0x40, 0xc8, 0x92, 0xb7, 0x11, 0xf7, 0x91, 0x52, 0x74, 0x86, 0xac, \
        0x4f, 0x10, 0x8a, 0xed, 0x1a, 0x59, 0xe8, 0xfd, 0x3c, 0x44, 0x2f, 0xbb, \
        0x12, 0xa3, 0xfa, 0xea, 0x28, 0x17, 0x78, 0x3f, 0x3c, 0x91, 0xad, 0xcf, \
        0x0b, 0xc0, 0xa8, 0xe7, 0xc9, 0x65, 0xfb, 0x86, 0xc8, 0x64, 0x0e, 0xfb, \
        0x82, 0xe9, 0xca, 0xb2, 0x45, 0x0d, 0x43, 0x5c, 0xff, 0x44, 0x00, 0x8f, \
        0x2b, 0x0b, 0x94, 0x6c, 0xd4, 0x8b, 0x6f, 0xee, 0xda, 0xe0, 0x1f, 0x5b, \
        0x7c, 0x4a, 0xcf, 0x38, 0xf6, 0xbf, 0x72, 0x4a, 0xe3, 0x14, 0x19, 0xbd, \
        0x42, 0xee, 0x14, 0x6a, 0x1a, 0x12, 0x57, 0x43, 0x7a, 0x09, 0x5a, 0x5d, \
        0x05, 0x20, 0xd3, 0x0c, 0xa2, 0x4e, 0x6e, 0x23, 0xb3, 0x91, 0xec, 0x57, \
        0x6a, 0x1a, 0x5e, 0x5f, 0xa5, 0x00, 0x89, 0x4f, 0x99, 0xf7, 0xf3, 0x22, \
        0x13, 0xd1, 0xab, 0xa9, 0x4a, 0x81, 0xd8, 0x1f, 0x4b, 0x5f, 0xdb, 0x36, \
        0x1b, 0xad, 0xe6, 0x6d, 0x3c, 0xfd, 0xb5, 0x44, 0x32, 0x5a, 0x9d, 0x9e, \
        0xaf, 0x88, 0xae, 0x4e, 0x72, 0x98, 0x90, 0x72, 0x40, 0x57, 0xb8, 0xf9, \
        0x81, 0x6f, 0x2e, 0x22, 0x55, 0x5a, 0x6a, 0xc3, 0xd0, 0x6e, 0xb7, 0xf4, \
        0x7c, 0x7e, 0x75, 0xd4, 0x0f, 0x28, 0x15, 0xe7, 0x8d, 0xb7, 0xa8, 0xa4, \
        0xd4, 0xa2, 0x14, 0x3c, 0x3f, 0x6c, 0x17, 0xee, 0x6a, 0x1b, 0x76, 0x2f, \
        0x50, 0x70, 0x6d, 0xf6, 0x52, 0x8d, 0x3c, 0x9d, 0x19, 0xcf, 0x50, 0x1a, \
        0x60, 0x65, 0xb4, 0xbe, 0xb1, 0x3a, 0x80, 0x70, 0x75, 0x42, 0x5f, 0xb9, \
        0x6c, 0xdc, 0x96, 0x9c, 0x53, 0x8d, 0xe6, 0x99, 0xef, 0x9c, 0xf0, 0x54, \
        0x5c, 0x0f, 0x7a, 0x28, 0xf3, 0x6e, 0x78 \
    }

// Server key with only 768 bits, signed by ROOT
#define TEST_SERVER_CERT_SMALL \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIChTCCAWwCAWUwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCQVUxEzARBgNV\r\n" \
    "BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\r\n" \
    "ZDEQMA4GA1UEAwwHQ0EgQ0VSVDAeFw0yMDA1MjYxNTI1NDlaFw0yMzAyMjAxNTI1\r\n" \
    "NDlaMGExCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK\r\n" \
    "DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxGjAYBgNVBAMMEVNNQUxMIFNFUlZF\r\n" \
    "UiBDRVJUMHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAO8tsNPT1L9BbU1pLM1AZmLq\r\n" \
    "W8wnwIZDkQ2riXQIvX7TWqIjAtfsAENM17SeGT/CsAJ+Y0E6QcONHsPDsHdS1SwS\r\n" \
    "Nuci94PvKNEP2vtY+7FzYPyt+EFk8A29fLG9yGF99QIDAQABMA0GCSqGSIb3DQEB\r\n" \
    "CwUAA4IBAgABcjioyWsRbHrLIYgz/3hrvdsZAJCNv0Zfuo867Iu1hNTHSflBsquO\r\n" \
    "89vF9jNGiZpaPi8Q0FpZxqaGZ4ebuUd8GwrSTPD53NYAu5RxjsV82udSe+bpDr61\r\n" \
    "YehoGyBzTvi73uxH0CzS2qQRGO/Ked9E3neyJTxUYPPuETapyysvj9pqGrot3oIu\r\n" \
    "O8DtBIrTen+TXFbCTbHPqjI5mEx22AgZDb+MM0oPSBwc0wlpGrU+hhdyHkn8IvX9\r\n" \
    "TMPfjyv7vHNXZDrZsRjBpSW5UJnGav6p322/o2B8nNod22FdkThOmjDBKa5T9vNI\r\n" \
    "3tS348NVx/laOyylktyoVXw98HibKF/H0Q==\r\n" \
    "-----END CERTIFICATE-----\r\n"

/*
 * Not everybody who includes this header needs to use all defined variables
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"

static const uint8_t rootCert[]   = TEST_ROOT_CA_CERT;
static const uint8_t imedCert[]   = TEST_IMED_CA_CERT;

static const uint8_t serverCert[]       = TEST_SERVER_CERT;
static const uint8_t serverCertDER[]    = TEST_SERVER_CERT_DER;
static const uint8_t serverCertRoot[]   = TEST_SERVER_CERT_ROOT;
static const uint8_t serverCertSha1[]   = TEST_SERVER_CERT_SHA1;
static const uint8_t serverCertEcc[]    = TEST_SERVER_CERT_ECC;
static const uint8_t serverCertSelf[]   = TEST_SERVER_CERT_SELF_SIGNED;
static const uint8_t serverCertSmall[]  = TEST_SERVER_CERT_SMALL;

#pragma GCC diagnostic pop
