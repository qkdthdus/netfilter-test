+-------------------------+
|      Application        |
| (curl, wget, etc.)      |
+------------+------------+
             |
             ▼
+-------------------------+
|        Kernel           |
| (iptables rule active)  |
| OUTPUT chain            |
|  TCP dst port 80        |
|      ▼                  |
| NFQUEUE (queue-num=0)   |
+------------+------------+
             |
             ▼
+-------------------------+
|    User Space Program   |
|  (libnetfilter_queue)   |
| - HTTP 분석             |
| - Host 헤더 확인        |
| - NF_ACCEPT or NF_DROP  |
+-------------------------+
