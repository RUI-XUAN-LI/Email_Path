import re
from collections import defaultdict

Received_template = [
    "from\s+(?P<from_name>[\w\.\-]+)\s+named\s+(?P<from_ip>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\;",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s*\[(?P<from_ip>[\d\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+(?P<tls>with\s+STARTTLS\s*\((?P<tls_version>version=[\w\.\d]+,\s*cipher=[\w\.\_]+)\))?\s+id\s+(?P<id>[\w]+);",
    "from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\;",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s*\[(?P<from_ip>[\d\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\;",
    "from\s+(?P<from_name>[\w\.\-]+)\(mailfrom:(?P<from_email>[\w\.\@\-]+)\s+fp:(?P<fp>[\w\.\-\_]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\;",
    "from\s+(?P<from_ip>[\d\.]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+)\;",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<mail_software>[\w\-]+)\)\s+whith\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+);",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<mail_software>[\w\-]+)\)\s+whith\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+);",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\)\r?\n\tby\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<mail_country>[\w\-]+)\)\s+with\s+(?P<protocol>\w+)\r?\n\tid\s+(?P<id>\w+)\r?\n\t",
    "from\s+(?P<from_name>[\w\.\-]+)\(mailfrom:(?P<from_email>[\w\.\@\-\_]+)\s+fp:(?P<fp>[\w\.\-\_]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\((?P<by_ip>[\d\.\:]+)\);",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\(\[(?P<from_ip>[\d\.\:]+)\]\)\s*\(envelope-sender\s+<(?P<envelope_sender>[\w\.\@\-]+)>\)\s*by\s+(?P<by_ip>[\d\.\:]+)\s+with\s+(?P<protocol>\w+)\s*for\s+<(?P<envelope_for>[\w\.\@\-]+)>;",
    "from\s+\[(?P<from_ip>[\d\.]+)\]\s+\(HELO\s+(?P<from_ip1>[\d\.]+)\)\s+\(\[(?P<from_ip2>[\d\.]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+);",
    "from\s+\?(?P<from_name>[\w\-]+)\?\s+\(HELO\s+(?P<from_ip>[\d\.]+)\)\s+\((?P<authenticated_sender>[\w\.\@\d\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+);",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\(HELO\s+\[(?P<from_ip>[\d\.]+)\]\)\s+\(\[(?P<from_ip1>[\d\.]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>[\w\.\-\/]+);",
    "from\s+\[(?P<from_ip>[\d\.\:]+)\]\s+\(helo=(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+)\s+for\s+(?P<envelope_for>[\w\.\@\-\+]+);",
    "from\s+\[(?P<from_ip>[\d\.\:]+)\]\s+\(port=(?P<from_port>\d+)\s+helo=(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\((?P<tls>[\w\d\.]+)\)\s+tls\s+(?P<cipher>[\w\-]+)\s+\((?P<mail_software>[\w\s\.\d]+)\)\s+id\s+(?P<id>\w+)\s+for\s+(?P<envelope_for>[\w\.\@\-\+]+);",
    "from\s+(?P<from_name>[\w\-\.]+)\s+\(HELO\s+(?P<from_hostname>[\w\-\d]+)\)\s+\((?P<email>[\w\.\@\-\+]+)\@\[(?P<from_ip>[\d\.]+)\]\)\s+by\s+(?P<by_ip>[\d\.]+)\s+with\s+(?P<protocol>\w+);",
    "from\s+(?P<from_name>\w+)\s+\(HELO\s+\?(?P<from_ip>[\w\.\-]+)\?\)\s+\((?P<email>[\w\.\-]+@[\w\.\-]+)@(?P<from_ip1>[\d\.]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\((?P<encryption>[\w\-]+(?:\s+encrypted)?)\)\s*;",
    "from\s+(?P<from_name>[\w\.\-\?]+)\s+\(HELO\s+\?(?P<from_ip>[\d\.]+)\?\)\s+\((?P<from_ip1>[\d\.]+)\)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>[\w\,\-]+);",
    "from\s+(?P<from_name>[\w\.\-\@]+)\s+\(HELO\s+(?P<from_hostname>[\w\.\-]+)\)\s+\((?P<email>[\w\.\-]+@[\w\.\-]+)@(?P<from_ip>[\d\.]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>[\w\-\.]+);",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+\((?P<from_name>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.]+)\]\)\s*by\s+(?P<by_hostname>[\w\.\-\s]+)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+)\s+envelope-from\s+<(?P<envelope_from>[\w\.\-]+@[\w\.\-]+)>\s*\(authenticated\s+bits=(?P<authenticated_bits>\d+)\);\s",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+\((?P<from_name>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.]+)\]\)\s+\(using\s+(?P<tls_version>TLSv[\d\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\((?P<cipher_bits>[\d\/]+)\s+bits\)\)\s+\((?P<certificate>[\w\.\-\s]+)\)\s+by\s+(?P<by_hostname>[\w\s\-]+)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+)\s+for\s+<(?P<envelope_for>[\w\.\@\-\_]+)>;",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+\((?P<from_name>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<protocol>\w+)\)\s+with\s+(?P<protocol1>\w+)\s+id\s+(?P<id>\w+);",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<mail_software>[\w\s\.\-]+(?:\([\w\s\.\-]+\))*)\)\s+id\s+(?P<id>\w+)\s+for\s+(?P<envelope_for>[\w\.\-]+@[\w\.\-]+\.[a-z]+);",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+\(\s*\[(?P<from_ip>[\d\.]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<protocol>\w+)\)\s+with\s+\r?\n?\t?id(?P<id>[\w\s]+);",
    "\(from\s+(?P<from_name>[\w\.\-\@]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<protocol>[\w\.\-/]+)\)\s+id\s+(?P<id>\w+)\s+for\s+(?P<envelope_for>[\w\.\-\@]+);",
    "from\s+(?P<from_name>[\w\.\-\@]+)\s*\(\s*\[(?P<from_ip>[\d\.]+)\]\s*\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s*\(\s*\[(?P<by_ip>[\d\.]+)\]\s*\)\s*;\s*\((?P<timezone>GMT[+-]\d{2}:\d{2})\)",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\-\.\_]+)\s+\[(?P<from_ip>[\w\.\-]+)\]\)\s+\(using\s+(?P<protocol>[\w\-\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-\.]+)\s+\((?P<bits>[\w\/]+)\s+bits\)\)\s+\((?P<certificate>[\w\-\.\s]+)\)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+\((?P<gateway>[\w\-\.\s]+)\)\s+with\s+(?P<protocol1>[\w\-\.]+)\s+id\s+(?P<id>[\w\s]+);",
    "from\s+(mail\s+pickup\s+service|(?P<from_name>[\[\]\w\.\-]*))\s*(\(\s*\[?(?P<from_ip>[a-f\d\.\:]+)(\%\d+|)\]?\s*\)|)\s*by\s*(?P<by_hostname>[\w\.\-]+)\s*(\(\s*\[?(?P<by_ip>[\d\.\:a-f]+)(\%\d+|)\]?\)|)\s*(over\s+TLS\s+secured\s+channel|)\s*with\s*(mapi|Microsoft\s+SMTP\s+Server|Microsoft\s+SMTPSVC(\((?P<server_version>[\d\.]+)\)|))\s*(\((TLS|version=(?P<tls>[\w\.]+)|)\,?\s*(cipher=(?P<cipher>[\w\_]+)|)\)|)\s*(id\s+(?P<id>[\d\.]+)|)",
    "\s*from\s+\[?(?P<from_ip>[\d\.\:]+)\]?\s*(\((port=\d+|)\s*helo=(?P<from_name>[\[\]\w\.\:\-]+)\)|)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s*(\((?P<cipher>[\w\.\:\_\-]+)\)|)\s*(\(Exim\s+(?P<exim_version>[\d\.\_]+)\)|)\s*\(envelope-from\s+<?(?P<envelope_from>[\w\@\-\.]*)>?\s*\)\s*id\s+(?P<id>[\w\-]+)\s*\s*(for\s+<?(?P<envelope_for>[\w\.\@]+)>?|)",
    "\s*from\s+(?P<from_hostname>[\w\.]+)\s+\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?(\:\d+|)\s*(helo\=\[?(?P<from_name>[\w\.\:\-]+)|)\]?\)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s+(\((?P<cipher>[\w\.\:\_]+)\)|)\s*\(Exim\s+(?P<exim_version>[\d\.\_]+)\)\s*\(envelope-from\s+\<(?P<envelope_from>[\w\@\-\.]+)\>\s*\)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+(?P<envelope_for>[\w\.\@]+)|)",
    "from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(Exim\s+(?P<version>[\d\.]+)\)\s+\(envelope-from\s+<*(?P<envelope_from>[\w\.\-\@]+)>*\)\s+id\s+(?P<id>[\w\.\-]+)\s+for\s+<?(?P<envelope_for>[\w\.\-\@]+)>?",
    "from\s+(?P<from_name>[\[\]\w\-\.]+)\s+\(((?P<from_hostname>[\w\.\-]+)|)\s*\[(?P<from_ip>[\da-f\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Oracle\s+Communications\s+Messaging\s+Server\s+(?P<oracle_version>[\w\.\-]+)(\([\d\.]+\)|)\s+(32bit|64bit|)\s*(\([^\)]+\)|)\)\s*with\s+(?P<protocol>\w+)\s+id\s+\<?(?P<id>[\w\@\.\-]+)\>?",
    "from\s+(?P<from_hostname>[\w\-\.]+)\s+\(\[(?P<from_ip>[\d\.\:a-f]+)\]\s+helo=(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(ASSP\s+(?P<assp_version>[\d\.]+)\s*\)",
    "from\s+(?P<from_hostname>[\[\]\d\w\.\-]+)\s+\(\[\[?(?P<from_ip>[\d\.]+)(\:\d+|)\]\s*(helo=(?P<from_name>[\w\.\-]+)|)\s*\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(envelope-from\s+\<?(?P<envelope_from>[^>]+)\>?\)\s+\(ecelerity\s+(?P<version>[\d\.]+)\s+r\([\w\-\:\.]+\)\)\s+with\s+(?P<protocol>\w+)\s*(\(cipher=(?P<cipher>[\w\-\_]+)\)|)\s*id\s+(?P<id>[\.\-\w\/]+)",
    "from\s+(?P<from_name>[\[\]\w\.\-]+)\s+\(((?P<from_hostname>[\w\.\-]+)|)\s*(\[(?P<from_ip>[\d\.\:a-f]+)\]|)\)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+(\([\w\.\-\=]+\)|)\s+with\s+(?P<protocol>\w+)\s+\(Nemesis\)\s+id\s+(?P<id>[\w\.\-]+)\s*(for\s+\<?(?P<envelope_for>[\w\.\@\-]+)\>?|)",
    "\(qmail\s+\d+\s+invoked\s+(from\s+network|)(by\s+uid\s+\w+|)\)",
    "from\s+\[?(?P<from_ip>[\d\.a-f\:]+)\]?\s+\(account\s+<?(?P<envelope_from>[\w\.\@\-]+)>?\s+HELO\s+(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]*)\s+\(CommuniGate\s+Pro\s+SMTP\s+(?P<version>[\d\.]+)\)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\-\.]+)\s+for\s+<?(?P<envelope_for>[\w\.\-\@]+)>?",
    "from\s+(?P<from_ip>[\d\.\:a-f]+)\s+\(SquirrelMail\s+authenticated\s+user\s+(?P<envelope_from>[\w\@\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)",
    "by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<protocol>\w+)\s+sendmail\s*(emulation|)\)",
    "from\s+(?P<from_name>[\[\]\w\.\-]+)\s+\(\[(?P<from_hostname>[\w\.\-]+)\]\s+\[(?P<from_ip>[\d\.a-f\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Sun\s+Java\(tm\)\s+System\s+Messaging\s+Server\s+(?P<version>[\w\.\-]+)\s+\d+bit\s+\(built\s+\w+\s+\d+\s+\d+\)\)\s+with\s+(?P<protocol>\w+)\s+id\s+<?(?P<id>[\w\.\-\@]+)>?",
    "from\s+(?P<from_name>[\w\.\-\[\]]+)\s+\((?P<from_ip>[\d\.a-f\:]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Axigen\)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\.\-]+)",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.a-f\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Horde\s+MIME\s+library\)\s+with\s+(?P<protocol>\w+)",
    "from\s+(?P<from_name>[\w\.\-\[\]]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(PGP\s+Universal\s+Service\)",
    "from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(Sophos\s+PureMessage\s+Version\s+(?P<version>[\d\.\-]+)\)\s+id\s+(?P<id>[\w\.\-]+)\s+for\s+(?P<envelope_for>[\w\.\-\@]+)",
    "by\s+(?P<by_ip>[\d\.\:a-f]+)\s+with\s+(?P<protocol>\w+)",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s*\(HELO\s+(?P<from_name>[\w\.\-]+)\)\s*\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?\)\s+by\s+(?P<by_hostname>[\w\.\-]+)(\s+\([\d\.]+\)|)\s*(with\s+(?P<protocol>\w+)|)\s*(id\s+(?P<id>[\w]+)|)(\(\-\)|)",
    "from\s+([\(\[](?P<from_ip>[\d\.\:a-f]+)[\)\]]|)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+id\s+(?P<id>\w+)\s*(with\s+(?P<protocol>\w+)|)\s*\s*(for\s+\<(?P<envelope_for>[\w\@\.\-]+)\>|)",
    "from\s+(?P<from_hostname>[\w\.]+)\s+(\(HELO\s+(?P<from_name>[\w\.\-]+)\)|)\s*(\((?P<from_ip>[\da-f\.\:]+)\)|)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<cipher>[\w\-]+)\s+encrypted\s+SMTP",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+(\(HELO\s+(?P<from_name>[\w\.\-]+)\)|)\s+\((?P<envelope_from>[\w\.]+\@[\w\.]+)\@(?P<from_ip>[\da-d\.\:]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)",
    "from\s+(?P<from_hostname>[\w\.\-]+)\s+\(HELO\s+(?P<from_name>[\w\.\-\?]+)\)\s+\(\w+\@[\w\.]+\@(?P<from_ip>[\d\.a-f\-]+)_\w+\)\s+by\s+(?P<by_hostname>[\w\.\-\:]+)\s+with\s+(?P<protocol>\w+)",
    "from\s+(?P<from_name>[\w\.\-\[\]]+)\s+\(\[(?P<from_ip>[\da-f\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(\[(?P<by_ip>[\d\.a-f\:]+)\]\)\s+with\s+(?P<protocol>\w+)",
    "from\s+(?P<from_name>[\w\.\-]+)\s*\(\s*(?P<from_ip>[a-f\d\.\:]+)\s*\)\s*#\|#\s*by\s+(?P<by_hostname>[\w\.\-]+)\s*\(\s*(?P<by_server>[\w\.\-]+)\s*\)\s*whith\s+ESMTP\s+id\s+(?P<id>[\w\-]+)\s*#\|#\s*(?P<date>[\w\,\s]+[\d]+(?:\s+[+\-]\d{4})?\s*\([A-Za-z]+\))$",
    "from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\d]+)\s+for\s+<(?P<envelope_for>[\w\.\@\-\+]+)>\s+\(version=(?P<tls_version>[\w\d_]+)\s+cipher=(?P<cipher>[\w\d_]+)\s+bits=(?P<bits>[\d\/]+)\);"
]

examples = [
    "from ip-172-31-41-56.ec2.internal (ec2-3-81-93-207.compute-1.amazonaws.com. [3.81.93.207]) by smtp.gmail.com with ESMTPSA id af79cd13be357-7a198fab08esm367497485a.23.2024.07.22.07.59.54 for <random@domain> (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256); Mon, 22 Jul 2024 07:59:54 -0700 (PDT)",
    "from DU0PR02MB8037.eurprd02.prod.outlook.com ([fe80::8cda:44fc:a66b:9ab5]) by DU0PR02MB8037.eurprd02.prod.outlook.com ([fe80::8cda:44fc:a66b:9ab5%3]) with mapi id 15.20.7784.016; Mon, 22 Jul 2024 14:59:01 +0000",
    "from mta1102-12.emaileu.clickdimensions.com (unknown [34.245.210.12])\r\nby qn-cmmxproxy-2.icoremail.net with SMTP id AQAAfwDX2hbyc55mX3RsAA--.56S3;\r\nMon, 22 Jul 2024 23:00:04 +0800 (CST)"
]

id_regexp = r'id\s+([^ ;#]+)(?=\s|;|#|\(|\)|$)'
date_regexp = r'(?:\w{1,5},\s*)?\d{1,5}\s+\w{1,5}\s+\d{1,5}\s+\d{1,5}:\d{1,5}:\d{1,5}(?:\.\d{1,5})?(?:\s+[+-]\d{1,5})?(?:\s+[+-]?[a-zA-Z0-9]+)?(?:\s+\([+-]?[a-zA-Z0-9]+\))?'


def match_remain(data_string):
    # Match domain names, IP addresses and email addresses
    hostname_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    if "by " in data_string:
        parts = data_string.split('by ', 1)
        from_part = parts[0].strip() if len(parts) > 0 else ""
        by_part = parts[1].strip() if len(parts) > 1 else ""
    else:
        from_part = data_string
        by_part = ""

    # 提取数据
    from_emails = re.findall(email_pattern, from_part)
    for from_email in from_emails:
        from_part = from_part.replace(from_email, "")

    from_hostnames = re.findall(hostname_pattern, from_part)
    from_ips = re.findall(ip_pattern, from_part)
    from_ipv6s = re.findall(ipv6_pattern, from_part)

    if "localhost" in from_part.lower() and "localhost" not in from_hostnames:
        from_hostnames.append("localhost")

    by_emails = re.findall(email_pattern, by_part)
    for by_email in by_emails:
        by_part = from_part.replace(by_email, "")

    by_hostnames = re.findall(hostname_pattern, by_part)
    by_ips = re.findall(ip_pattern, by_part)
    by_ipv6s = re.findall(ipv6_pattern, by_part)

    if "localhost" in by_part.lower() and "localhost" in by_hostnames:
        by_hostnames.append("localhost")

    extracted_data = {
        "from_hostname": from_hostnames,
        "from_ip": from_ips,
        "from_ipv6": from_ipv6s,
        "from_email": from_emails,
        "by_hostname": by_hostnames,
        "by_ip": by_ips,
        "by_ipv6": by_ipv6s,
        "by_email": by_emails
    }

    result = {}
    for key, values in extracted_data.items():
        if values:
            for i, value in enumerate(values):
                if i == 0:
                    result[key] = value
                else:
                    result[f"{key}{i}"] = value

    return result


if __name__ == '__main__':
    for raw_received in examples:
        raw_received = raw_received.replace("\r", " ")
        raw_received = raw_received.replace("\n", " ")
        raw_received = raw_received.replace("\t", " ")

        # Process the ID field and the date field first
        id_list = re.findall(id_regexp, raw_received)
        date_list = re.findall(date_regexp, raw_received)

        id = id_list[0] if id_list is not None and len(id_list) > 0 else "none"
        date = date_list[0] if date_list is not None and len(date_list) > 0 else "none"

        raw_received = re.sub(id_regexp, 'id 123', raw_received)
        raw_received = re.sub(date_regexp, '', raw_received)

        # Match with regular expression templates
        match = False
        match_dict = defaultdict(str)
        for regex in Received_template:
            match_result = re.match(regex, raw_received, re.IGNORECASE | re.DOTALL)
            if match_result:
                match = True
                match_dict = match_result.groupdict()

        if match:
            match_dict["id"] = id
            match_dict["date"] = date
            print(match_dict)
        else:
            # Extract key information directly
            if "from " in raw_received or "by " in raw_received:
                match_dict = match_remain(raw_received)
                if match_dict:
                    match_dict["id"] = id
                    match_dict["date"] = date
                    print(match_dict)
                else:
                    print("NO match")
            else:
                print("Error format")
