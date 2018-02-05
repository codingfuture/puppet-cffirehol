#
# Copyright 2016-2018 (c) Andrey Galkin
#


# Please see README
class cffirehol::debian::apt {
    if $::cffirehol::debian::firehol_apt_url {
        apt::key {'firehol':
            id      => '5D6CBEBE280C28B18F77C1FEABE831B7ABA014C4',
            server  => 'not.valid.server',
            content => '
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQINBFabi7IBEADBa+AfvNbrqrW7np9hMlUTFvfqrvCbo27kMcaS1bCoHQKVDxCc
zTjfz5lIQZGCX+LHWeOmng7x8eFb09eZUutzT1lgAvHEYxOnJYrIRhelw0u78J/L
PUyzcIWFLACcp1IsK6dNSV6LboYS5shhLlGgoc/keHz4p/DRS2xHudHASvRd8rnH
TELtxJOLloVWpqB0EBGxIP+SBdVnEmeWfP1oOZWbQMdY2WHQA2N/BS1TdE+iGZJN
cKox56JzDZ+5/1tXp3OrttINqdFqFJ4Qn4G1sj2qzSjg85NDeBKxRp22ds0N7xKp
Zu8ksKsRqvkaqKWuRXFdqIosbGI9MYhW4oA5zajevM67ZElX0qFKNp1mH76vtoOV
pMU/8Z43YPCf6cnvwymoK0TeFOlN9mMW/4rT7QrO2hy/964vcx4v/XNHCKGfz/ae
rnDPg+mviAmVvv/TcUzmlbhqxeo6pMWNODqf8CfOJCHKJcADRBkuiCZckqgVg2GC
QJ62pd6sleqIj/fpgEGvoi8IsPx2dcw51HQRg60tJEH3EM5x6LFn28xLP4W0ykzE
sBMcO+vjqaXhDCVO+TC5uRACgrE2HqZFKP/vBgpI1qSdQRnopf6kWCtHv09ZDMvP
OVvyOcU8UcsSztd3TGPvc1J3GOKaYmZcn0j6wazPrJp8dFtKRLuQQzPlKwARAQAB
tB9MYXVuY2hwYWQgUFBBIGZvciBBbmRyZXkgR2Fsa2luiQI4BBMBAgAiBQJWm4uy
AhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRCr6DG3q6AUxIGrD/4w9/nK
gYXILiHEGCPtsWtDjwWYw8S0WGfRB71pNA/pSHJTHyZ0C/1chzacNqt7dIvzSyef
Tr2KBip+a2e6fRAdg9pAxv8Gj5LWVQC/ng6aHgcMorKfwaEz+R86z+4u3x6OMFHn
rjeIp/B3hCllKX7sqoUm9hAEDlm4ARtwyKBIku8NB0/1TIfmoVBME7iOaALpQPKj
c8gF8+QykU+XLHFBFtiGYln+1Cy/4sZ1Pk+amn9gWGvv3CQyqSCPm0363M6yitqk
59x14NjmZUj7QPNjwgFDuR1Wat30DLe8IrO9JSFxPDV1p6f22AzAHYYPBwyylhPX
dRmhXLUwVCvG+P0VcNmXcWSqx28GRgXinHqQIh1LZsbNkYjaK0xYrphMpU+ghiNq
lAIXM7hacbszSw+Bg9MDCHJw7KKJg2UOS+yZCEmGd4kvOwFJpFX86Amt3xAhthbU
8GQnu2RBNsjsZuMChxIOJyrBMxIDFGXrQBUp722T5dfqjX+Js4joOAfDmCcw/Xq/
B3ZLrtYI6M2nbGbz7dOiDR88JKIhTJQShse8e7jmBFKNKXHeeMLdgTeRNSQ6PVgq
bvSjdxYnZp/buoz4LdrWBYcv54jaZve7hfmd7a7NdMOUVz4x15Bwp9LXFClXRTJ2
T5EURECAHdQRiIB/zKAgYjuzF/wNm33bB2zVYA==
=vwVa
-----END PGP PUBLIC KEY BLOCK-----
',
        }
        apt::source { 'firehol':
            location => $::cffirehol::debian::firehol_apt_url,
            release  => $::cffirehol::debian::firehol_apt_release,
            repos    => 'main',
            include  => { src => false },
            pin      => 1010,
            require  => Apt::Key['firehol'],
            notify   => Class['apt::update'],
            before   => Package['firehol'],
        }
    }
}
