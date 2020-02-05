![logo](https://upload.wikimedia.org/wikipedia/commons/a/a5/VirusTotal-logo.png)
## VirusTotalVersion3
### Installation
```bash
$ git clone https://github.com/kmuinfosec/VirusTotalVersion3.git
$ cd VirusTotalVersion3
$ pip install requirement.txt
```

### Usage
```python
import json
import VirusTotalVersion3

public_api = VirusTotalVersion3.PublicAPI('YOUR-API-KEY')
report = public_api.get_file_info('000052c5b5ff444f543689508df67340')
with open('000052c5b5ff444f543689508df67340.json', 'w') as f:
    json.dump(report, f, indet=4)
```

### Output
```json
{
    "data": {
        "attributes": {
            "authentihash": "befdcfe438efc1c46e4e82d728b7afd72858388957c4236db9e6f7a102b4d43b",
            "creation_date": 1288815443,
            "exiftool": {
                "CodeSize": 1024,
                "EntryPoint": "0x1184",
                "FileType": "Win32 DLL",
                "FileTypeExtension": "dll",
                "ImageFileCharacteristics": "Executable, No line numbers, No symbols, 32-bit, DLL",
                "ImageVersion": "0.0",
                "InitializedDataSize": 1536,
                "LinkerVersion": "5.12",
                "MIMEType": "application/octet-stream",
                "MachineType": "Intel 386 or later, and compatibles",
                "OSVersion": "4.0",
                "PEType": "PE32",
                "Subsystem": "Windows GUI",
                "SubsystemVersion": "4.0",
                "TimeStamp": "2010:11:03 21:17:23+01:00",
                "UninitializedDataSize": 0
            },
            "first_submission_date": 1408464826,
            "last_analysis_date": 1580829374,
            "last_analysis_results": {
                "ALYac": {
                    "category": "malicious",
                    "engine_name": "ALYac",
                    "engine_update": "20200204",
                    "engine_version": "1.1.1.5",
                    "method": "blacklist",
                    "result": "Trojan.Agent.EBDQ"
                },
                "APEX": {
                    "category": "malicious",
                    "engine_name": "APEX",
                    "engine_update": "20200204",
                    "engine_version": "5.114",
                    "method": "blacklist",
                    "result": "Malicious"
                },
                "AVG": {
                    "category": "malicious",
                    "engine_name": "AVG",
                    "engine_update": "20200204",
                    "engine_version": "18.4.3895.0",
                    "method": "blacklist",
                    "result": "Win32:GenMalicious-FOR [Trj]"
                },
                "Acronis": {
                    "category": "malicious",
                    "engine_name": "Acronis",
                    "engine_update": "20200203",
                    "engine_version": "1.1.1.58",
                    "method": "blacklist",
                    "result": "suspicious"
                },
                "Ad-Aware": {
                    "category": "malicious",
                    "engine_name": "Ad-Aware",
                    "engine_update": "20200204",
                    "engine_version": "3.0.5.370",
                    "method": "blacklist",
                    "result": "Trojan.Agent.EBDQ"
                },
                "AegisLab": {
                    "category": "malicious",
                    "engine_name": "AegisLab",
                    "engine_update": "20200204",
                    "engine_version": "4.2",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter.tpzR"
                },
                "AhnLab-V3": {
                    "category": "malicious",
                    "engine_name": "AhnLab-V3",
                    "engine_update": "20200204",
                    "engine_version": "3.17.1.26513",
                    "method": "blacklist",
                    "result": "Trojan/Win32.Starter.R1831"
                },
                "Alibaba": {
                    "category": "malicious",
                    "engine_name": "Alibaba",
                    "engine_update": "20190527",
                    "engine_version": "0.3.0.5",
                    "method": "blacklist",
                    "result": "Trojan:Win32/Ramnit.0ebed10a"
                },
                "Antiy-AVL": {
                    "category": "undetected",
                    "engine_name": "Antiy-AVL",
                    "engine_update": "20200204",
                    "engine_version": "3.0.0.1",
                    "method": "blacklist",
                    "result": null
                },
                "Arcabit": {
                    "category": "malicious",
                    "engine_name": "Arcabit",
                    "engine_update": "20200204",
                    "engine_version": "1.0.0.869",
                    "method": "blacklist",
                    "result": "Trojan.Agent.EBDQ"
                },
                "Avast": {
                    "category": "malicious",
                    "engine_name": "Avast",
                    "engine_update": "20200204",
                    "engine_version": "18.4.3895.0",
                    "method": "blacklist",
                    "result": "Win32:GenMalicious-FOR [Trj]"
                },
                "Avast-Mobile": {
                    "category": "undetected",
                    "engine_name": "Avast-Mobile",
                    "engine_update": "20200130",
                    "engine_version": "200130-00",
                    "method": "blacklist",
                    "result": null
                },
                "Avira": {
                    "category": "malicious",
                    "engine_name": "Avira",
                    "engine_update": "20200204",
                    "engine_version": "8.3.3.8",
                    "method": "blacklist",
                    "result": "W32/Run.Ramnit.C"
                },
                "Baidu": {
                    "category": "malicious",
                    "engine_name": "Baidu",
                    "engine_update": "20190318",
                    "engine_version": "1.0.0.2",
                    "method": "blacklist",
                    "result": "Win32.Trojan.Ramnit.d"
                },
                "BitDefender": {
                    "category": "malicious",
                    "engine_name": "BitDefender",
                    "engine_update": "20200204",
                    "engine_version": "7.2",
                    "method": "blacklist",
                    "result": "Trojan.Agent.EBDQ"
                },
                "BitDefenderTheta": {
                    "category": "malicious",
                    "engine_name": "BitDefenderTheta",
                    "engine_update": "20200120",
                    "engine_version": "7.2.37796.0",
                    "method": "blacklist",
                    "result": "Gen:NN.ZedlaF.34084.aq4@aGBltti"
                },
                "Bkav": {
                    "category": "malicious",
                    "engine_name": "Bkav",
                    "engine_update": "20200203",
                    "engine_version": "1.3.0.9899",
                    "method": "blacklist",
                    "result": "W32.StarterYY.Trojan"
                },
                "CAT-QuickHeal": {
                    "category": "malicious",
                    "engine_name": "CAT-QuickHeal",
                    "engine_update": "20200204",
                    "engine_version": "14.00",
                    "method": "blacklist",
                    "result": "Trojan.Starter.YY4"
                },
                "CMC": {
                    "category": "malicious",
                    "engine_name": "CMC",
                    "engine_update": "20190321",
                    "engine_version": "1.1.0.977",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter!O"
                },
                "ClamAV": {
                    "category": "malicious",
                    "engine_name": "ClamAV",
                    "engine_update": "20200204",
                    "engine_version": "0.102.1.0",
                    "method": "blacklist",
                    "result": "Win.Trojan.Starter-290"
                },
                "Comodo": {
                    "category": "malicious",
                    "engine_name": "Comodo",
                    "engine_update": "20200204",
                    "engine_version": "32044",
                    "method": "blacklist",
                    "result": "TrojWare.Win32.Starter.yy@2n6jmr"
                },
                "CrowdStrike": {
                    "category": "malicious",
                    "engine_name": "CrowdStrike",
                    "engine_update": "20190702",
                    "engine_version": "1.0",
                    "method": "blacklist",
                    "result": "win/malicious_confidence_100% (D)"
                },
                "Cybereason": {
                    "category": "type-unsupported",
                    "engine_name": "Cybereason",
                    "engine_update": "20180308",
                    "engine_version": null,
                    "method": "blacklist",
                    "result": null
                },
                "Cylance": {
                    "category": "malicious",
                    "engine_name": "Cylance",
                    "engine_update": "20200204",
                    "engine_version": "2.3.1.101",
                    "method": "blacklist",
                    "result": "Unsafe"
                },
                "Cyren": {
                    "category": "malicious",
                    "engine_name": "Cyren",
                    "engine_update": "20200204",
                    "engine_version": "6.2.2.2",
                    "method": "blacklist",
                    "result": "W32/Ramnit.E.gen!Eldorado"
                },
                "DrWeb": {
                    "category": "malicious",
                    "engine_name": "DrWeb",
                    "engine_update": "20200204",
                    "engine_version": "7.0.44.12030",
                    "method": "blacklist",
                    "result": "Trojan.Starter.2386"
                },
                "ESET-NOD32": {
                    "category": "malicious",
                    "engine_name": "ESET-NOD32",
                    "engine_update": "20200204",
                    "engine_version": "20784",
                    "method": "blacklist",
                    "result": "Win32/Ramnit.F"
                },
                "Emsisoft": {
                    "category": "malicious",
                    "engine_name": "Emsisoft",
                    "engine_update": "20200204",
                    "engine_version": "2018.12.0.1641",
                    "method": "blacklist",
                    "result": "Trojan.Agent.EBDQ (B)"
                },
                "Endgame": {
                    "category": "malicious",
                    "engine_name": "Endgame",
                    "engine_update": "20200131",
                    "engine_version": "3.0.16",
                    "method": "blacklist",
                    "result": "malicious (high confidence)"
                },
                "F-Prot": {
                    "category": "malicious",
                    "engine_name": "F-Prot",
                    "engine_update": "20200204",
                    "engine_version": "4.7.1.166",
                    "method": "blacklist",
                    "result": "W32/Ramnit.E.gen!Eldorado"
                },
                "F-Secure": {
                    "category": "malicious",
                    "engine_name": "F-Secure",
                    "engine_update": "20200204",
                    "engine_version": "12.0.86.52",
                    "method": "blacklist",
                    "result": "Malware.W32/Run.Ramnit.C"
                },
                "FireEye": {
                    "category": "malicious",
                    "engine_name": "FireEye",
                    "engine_update": "20200204",
                    "engine_version": "29.7.0.0",
                    "method": "blacklist",
                    "result": "Generic.mg.000052c5b5ff444f"
                },
                "Fortinet": {
                    "category": "malicious",
                    "engine_name": "Fortinet",
                    "engine_update": "20200204",
                    "engine_version": "6.2.137.0",
                    "method": "blacklist",
                    "result": "W32/Generic.AC.A0B!tr"
                },
                "GData": {
                    "category": "malicious",
                    "engine_name": "GData",
                    "engine_update": "20200204",
                    "engine_version": "A:25.24796B:26.17598",
                    "method": "blacklist",
                    "result": "Win32.Virus.Ramnit.E"
                },
                "Ikarus": {
                    "category": "malicious",
                    "engine_name": "Ikarus",
                    "engine_update": "20200204",
                    "engine_version": "0.1.5.2",
                    "method": "blacklist",
                    "result": "Trojan.Rund"
                },
                "Invincea": {
                    "category": "malicious",
                    "engine_name": "Invincea",
                    "engine_update": "20191211",
                    "engine_version": "6.3.6.26157",
                    "method": "blacklist",
                    "result": "heuristic"
                },
                "Jiangmin": {
                    "category": "malicious",
                    "engine_name": "Jiangmin",
                    "engine_update": "20200204",
                    "engine_version": "16.0.100",
                    "method": "blacklist",
                    "result": "Trojan/Starter.if"
                },
                "K7AntiVirus": {
                    "category": "malicious",
                    "engine_name": "K7AntiVirus",
                    "engine_update": "20200204",
                    "engine_version": "11.91.33190",
                    "method": "blacklist",
                    "result": "EmailWorm ( 0016c8f31 )"
                },
                "K7GW": {
                    "category": "malicious",
                    "engine_name": "K7GW",
                    "engine_update": "20200204",
                    "engine_version": "11.91.33191",
                    "method": "blacklist",
                    "result": "EmailWorm ( 0016c8f31 )"
                },
                "Kaspersky": {
                    "category": "malicious",
                    "engine_name": "Kaspersky",
                    "engine_update": "20200204",
                    "engine_version": "15.0.1.13",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter.yy"
                },
                "Kingsoft": {
                    "category": "malicious",
                    "engine_name": "Kingsoft",
                    "engine_update": "20200204",
                    "engine_version": "2013.8.14.323",
                    "method": "blacklist",
                    "result": "Win32.Troj.Agent.ac.3584"
                },
                "MAX": {
                    "category": "malicious",
                    "engine_name": "MAX",
                    "engine_update": "20200204",
                    "engine_version": "2019.9.16.1",
                    "method": "blacklist",
                    "result": "malware (ai score=88)"
                },
                "Malwarebytes": {
                    "category": "undetected",
                    "engine_name": "Malwarebytes",
                    "engine_update": "20200204",
                    "engine_version": "3.6.4.330",
                    "method": "blacklist",
                    "result": null
                },
                "MaxSecure": {
                    "category": "malicious",
                    "engine_name": "MaxSecure",
                    "engine_update": "20200204",
                    "engine_version": "1.0.0.1",
                    "method": "blacklist",
                    "result": "Virus.W32.Nimnul.Runner"
                },
                "McAfee": {
                    "category": "malicious",
                    "engine_name": "McAfee",
                    "engine_update": "20200204",
                    "engine_version": "6.0.6.653",
                    "method": "blacklist",
                    "result": "W32/Ramnit.w"
                },
                "McAfee-GW-Edition": {
                    "category": "malicious",
                    "engine_name": "McAfee-GW-Edition",
                    "engine_update": "20200204",
                    "engine_version": "v2017.3010",
                    "method": "blacklist",
                    "result": "W32/Ramnit.w"
                },
                "MicroWorld-eScan": {
                    "category": "malicious",
                    "engine_name": "MicroWorld-eScan",
                    "engine_update": "20200204",
                    "engine_version": "14.0.405.0",
                    "method": "blacklist",
                    "result": "Trojan.Agent.EBDQ"
                },
                "Microsoft": {
                    "category": "malicious",
                    "engine_name": "Microsoft",
                    "engine_update": "20200204",
                    "engine_version": "1.1.16700.3",
                    "method": "blacklist",
                    "result": "Trojan:Win32/Ramnit.C"
                },
                "NANO-Antivirus": {
                    "category": "malicious",
                    "engine_name": "NANO-Antivirus",
                    "engine_update": "20200204",
                    "engine_version": "1.0.134.25031",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter.eralss"
                },
                "Paloalto": {
                    "category": "malicious",
                    "engine_name": "Paloalto",
                    "engine_update": "20200204",
                    "engine_version": "1.0",
                    "method": "blacklist",
                    "result": "generic.ml"
                },
                "Panda": {
                    "category": "malicious",
                    "engine_name": "Panda",
                    "engine_update": "20200204",
                    "engine_version": "4.6.4.2",
                    "method": "blacklist",
                    "result": "Generic Malware"
                },
                "Qihoo-360": {
                    "category": "malicious",
                    "engine_name": "Qihoo-360",
                    "engine_update": "20200204",
                    "engine_version": "1.0.0.1120",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter.A"
                },
                "Rising": {
                    "category": "malicious",
                    "engine_name": "Rising",
                    "engine_update": "20200204",
                    "engine_version": "25.0.0.24",
                    "method": "blacklist",
                    "result": "Worm.Ramnit!1.A0D4 (CLOUD)"
                },
                "SUPERAntiSpyware": {
                    "category": "malicious",
                    "engine_name": "SUPERAntiSpyware",
                    "engine_update": "20200131",
                    "engine_version": "5.6.0.1032",
                    "method": "blacklist",
                    "result": "Trojan.Agent/Gen-Ramnit"
                },
                "Sangfor": {
                    "category": "malicious",
                    "engine_name": "Sangfor",
                    "engine_update": "20200114",
                    "engine_version": "1.0",
                    "method": "blacklist",
                    "result": "Malware"
                },
                "SentinelOne": {
                    "category": "malicious",
                    "engine_name": "SentinelOne",
                    "engine_update": "20191218",
                    "engine_version": "1.12.1.57",
                    "method": "blacklist",
                    "result": "DFI - Malicious PE"
                },
                "Sophos": {
                    "category": "malicious",
                    "engine_name": "Sophos",
                    "engine_update": "20200204",
                    "engine_version": "4.98.0",
                    "method": "blacklist",
                    "result": "W32/Ramnit-BO"
                },
                "Symantec": {
                    "category": "malicious",
                    "engine_name": "Symantec",
                    "engine_update": "20200204",
                    "engine_version": "1.11.0.0",
                    "method": "blacklist",
                    "result": "W32.Ramnit.B"
                },
                "SymantecMobileInsight": {
                    "category": "type-unsupported",
                    "engine_name": "SymantecMobileInsight",
                    "engine_update": "20200113",
                    "engine_version": "2.0",
                    "method": "blacklist",
                    "result": null
                },
                "TACHYON": {
                    "category": "malicious",
                    "engine_name": "TACHYON",
                    "engine_update": "20200204",
                    "engine_version": "2020-02-04.04",
                    "method": "blacklist",
                    "result": "Trojan/W32.Starter.3584"
                },
                "Tencent": {
                    "category": "malicious",
                    "engine_name": "Tencent",
                    "engine_update": "20200204",
                    "engine_version": "1.0.0.1",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Agent.aae"
                },
                "TotalDefense": {
                    "category": "malicious",
                    "engine_name": "TotalDefense",
                    "engine_update": "20200204",
                    "engine_version": "37.1.62.1",
                    "method": "blacklist",
                    "result": "Win32/Ramnit.H"
                },
                "Trapmine": {
                    "category": "malicious",
                    "engine_name": "Trapmine",
                    "engine_update": "20200123",
                    "engine_version": "3.2.22.914",
                    "method": "blacklist",
                    "result": "malicious.high.ml.score"
                },
                "TrendMicro": {
                    "category": "malicious",
                    "engine_name": "TrendMicro",
                    "engine_update": "20200204",
                    "engine_version": "11.0.0.1006",
                    "method": "blacklist",
                    "result": "TROJ_STARTER.SM"
                },
                "TrendMicro-HouseCall": {
                    "category": "malicious",
                    "engine_name": "TrendMicro-HouseCall",
                    "engine_update": "20200204",
                    "engine_version": "10.0.0.1040",
                    "method": "blacklist",
                    "result": "TROJ_STARTER.SM"
                },
                "Trustlook": {
                    "category": "type-unsupported",
                    "engine_name": "Trustlook",
                    "engine_update": "20200204",
                    "engine_version": "1.0",
                    "method": "blacklist",
                    "result": null
                },
                "VBA32": {
                    "category": "malicious",
                    "engine_name": "VBA32",
                    "engine_update": "20200204",
                    "engine_version": "4.3.0",
                    "method": "blacklist",
                    "result": "Trojan.Starter"
                },
                "VIPRE": {
                    "category": "malicious",
                    "engine_name": "VIPRE",
                    "engine_update": "20200204",
                    "engine_version": "81282",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Ramnit.c (v)"
                },
                "ViRobot": {
                    "category": "malicious",
                    "engine_name": "ViRobot",
                    "engine_update": "20200204",
                    "engine_version": "2014.3.20.0",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter.3584"
                },
                "Webroot": {
                    "category": "malicious",
                    "engine_name": "Webroot",
                    "engine_update": "20200204",
                    "engine_version": "1.0.0.403",
                    "method": "blacklist",
                    "result": "W32.RamNit.Gen"
                },
                "Yandex": {
                    "category": "malicious",
                    "engine_name": "Yandex",
                    "engine_update": "20200204",
                    "engine_version": "5.5.2.24",
                    "method": "blacklist",
                    "result": "Trojan.Ramnit!iQNQL6zS3w0"
                },
                "Zillya": {
                    "category": "malicious",
                    "engine_name": "Zillya",
                    "engine_update": "20200204",
                    "engine_version": "2.0.0.4015",
                    "method": "blacklist",
                    "result": "Trojan.Starter.Win32.1038"
                },
                "ZoneAlarm": {
                    "category": "malicious",
                    "engine_name": "ZoneAlarm",
                    "engine_update": "20200204",
                    "engine_version": "1.0",
                    "method": "blacklist",
                    "result": "Trojan.Win32.Starter.yy"
                },
                "Zoner": {
                    "category": "undetected",
                    "engine_name": "Zoner",
                    "engine_update": "20200204",
                    "engine_version": "1.0.0.1",
                    "method": "blacklist",
                    "result": null
                },
                "eGambit": {
                    "category": "malicious",
                    "engine_name": "eGambit",
                    "engine_update": "20200204",
                    "engine_version": null,
                    "method": "blacklist",
                    "result": "Unsafe.AI_Score_89%"
                }
            },
            "last_analysis_stats": {
                "confirmed-timeout": 0,
                "failure": 0,
                "harmless": 0,
                "malicious": 68,
                "suspicious": 0,
                "timeout": 0,
                "type-unsupported": 3,
                "undetected": 4
            },
            "last_modification_date": 1580829426,
            "last_submission_date": 1580007008,
            "magic": "PE32 executable for MS Windows (DLL) (GUI) Intel 80386 32-bit",
            "md5": "000052c5b5ff444f543689508df67340",
            "meaningful_name": "000052c5b5ff444f543689508df67340.virobj",
            "names": [
                "0821a97827a25e3694134ac261189f61f06b010b741d66c933833a7ea53bad3c",
                "000052c5b5ff444f543689508df67340.virobj",
                "000052c5b5ff444f543689508df67340"
            ],
            "pe_info": {
                "entry_point": 4484,
                "imphash": "b6f391375d741ab65301de3824d105be",
                "imports": {
                    "kernel32.dll": [
                        "CreateMutexA",
                        "CreateProcessA",
                        "ReleaseMutex",
                        "lstrlenA",
                        "GetLastError",
                        "lstrcpyA",
                        "CloseHandle",
                        "GetModuleFileNameA"
                    ]
                },
                "machine_type": 332,
                "sections": [
                    {
                        "entropy": 3.71,
                        "md5": "3f45a5a912cd87951e4b969fa06a1d42",
                        "name": ".text",
                        "raw_size": 1024,
                        "virtual_address": 4096,
                        "virtual_size": 566
                    },
                    {
                        "entropy": 2.7,
                        "md5": "36d40f34d9ca870f8f6d54ad2f0649e4",
                        "name": ".rdata",
                        "raw_size": 512,
                        "virtual_address": 8192,
                        "virtual_size": 307
                    },
                    {
                        "entropy": 0.74,
                        "md5": "dd1958a30e60f03fb7b8636802d664f9",
                        "name": ".data",
                        "raw_size": 512,
                        "virtual_address": 12288,
                        "virtual_size": 302
                    },
                    {
                        "entropy": 0.42,
                        "md5": "3c211ac96cc90a1e7fb292683a6ac246",
                        "name": ".reloc",
                        "raw_size": 512,
                        "virtual_address": 16384,
                        "virtual_size": 52
                    }
                ],
                "timestamp": 1288815443
            },
            "reputation": 0,
            "sha1": "b24508e3d24c3ea319132871c218267f0bb80dd1",
            "sha256": "0821a97827a25e3694134ac261189f61f06b010b741d66c933833a7ea53bad3c",
            "size": 3584,
            "ssdeep": "24:eH1GSY19vPQeDR21SMwh0tYPFThtdnIUovRidLYH/B/gUoe:yY/gqQ1hWMStdnapidc5j",
            "tags": [
                "pedll"
            ],
            "times_submitted": 6,
            "total_votes": {
                "harmless": 0,
                "malicious": 0
            },
            "trid": [
                {
                    "file_type": "Win32 Executable (generic)",
                    "probability": 42.7
                },
                {
                    "file_type": "OS/2 Executable (generic)",
                    "probability": 19.2
                },
                {
                    "file_type": "Generic Win/DOS Executable",
                    "probability": 18.9
                },
                {
                    "file_type": "DOS Executable Generic",
                    "probability": 18.9
                }
            ],
            "type_description": "Win32 DLL",
            "type_tag": "pedll",
            "unique_sources": 3
        },
        "id": "0821a97827a25e3694134ac261189f61f06b010b741d66c933833a7ea53bad3c",
        "links": {
            "self": "https://www.virustotal.com/api/v3/files/0821a97827a25e3694134ac261189f61f06b010b741d66c933833a7ea53bad3c"
        },
        "type": "file"
    }
}
```

### License
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)