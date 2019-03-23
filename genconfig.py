'''
A simple python script created to generate GrayLog pipeline rules for pfSense.
Copyright (C) 2019 Ashlord666

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import sys

def genblock(*args):
    
    # common fields
    fields = []
    regexstring = r'"^.*,(in|out),'
    if 'ipv4' in args:
        regexstring += r'4,'
    elif 'ipv6' in args:
        regexstring += r'6,'
    else:
        sys.exit("Woah, that is unexpected...")
    
    fields.append("RuleNumber")
    fields.append("SubRuleNumber")
    fields.append("Anchor")
    fields.append("Tracker")
    fields.append("Interface")
    fields.append("Reason")
    fields.append("Action")
    fields.append("Direction")
    fields.append("IPVersion")

    # ipv4
    if 'ipv4' in args:
        fields.append("TOS")
        fields.append("ECN")
        fields.append("TTL")
        fields.append("ID")
        fields.append("Offset")
        fields.append("Flags")
        fields.append("ProtocolID")
        fields.append("Protocol")
    
    # ipv6
    if 'ipv6' in args:
        fields.append("Class")
        fields.append("FlowLabel")
        fields.append("HopLimit")
        fields.append("Protocol")
        fields.append("ProtocolID")

    # ipv4 or ipv6
    if 'ipv4' in args or 'ipv6' in args:
        fields.append("Length")
        fields.append("SourceIP")
        fields.append("DestIP")

    # tcp and udp
    if 'udp' in args:
        regexstring += r'.*,udp,.*'
        fields.append("SourcePort")
        fields.append("DestPort")
        fields.append("DataLength")

    # tcp only
    if 'tcp' in args:
        regexstring += r'.*,tcp,.*'
        fields.append("SourcePort")
        fields.append("DestPort")
        fields.append("DataLength")
        fields.append("TCPFlags")
        fields.append("Sequence")
        fields.append("ACK")
        fields.append("Window")
        fields.append("URG")
        fields.append("Options")

    # icmp echo request/reply
    if 'icmp-echo' in args:
        regexstring += r'.*,(request|reply),.*'
        fields.append("ICMPType")
        fields.append("ICMPID")
        fields.append("ICMPSeq")

    # icmp protocol unreachable
    if 'icmp-protocol-unreachable' in args:
        regexstring += r'.*,unreachproto,.*'
        fields.append("ICMPType")
        fields.append("DestIP")
        fields.append("ProtocolID")      

    # icmp port unreachable
    if 'icmp-port-unreachable' in args:
        regexstring += r'.*,unreachport,.*'
        fields.append("ICMPType")
        fields.append("DestIP")
        fields.append("ProtocolID")   
        fields.append("DestPort")   

    # icmp unreachable
    if 'icmp-unreachable' in args:
        regexstring += r'.*,(unreach|timexceed|paramprob|redirect|maskreply),.*'
        fields.append("ICMPType")
        fields.append("ICMPDesc")

    # icmp need frag
    if 'icmp-need-frag' in args:
        regexstring += r'.*,needfrag,.*'
        fields.append("ICMPType")
        fields.append("DestIP")
        fields.append("MTU")      

    # icmp tstamp
    if 'icmp-tstamp' in args:
        regexstring += r'.*,tstamp,.*'
        fields.append("ICMPType")
        fields.append("ICMPID")
        fields.append("ICMPSeq")

    # icmp tstamp reply
    if 'icmp-tstamp-reply' in args:
        regexstring += r'.*,tstampreply,.*'
        fields.append("ICMPType")
        fields.append("ICMPID")
        fields.append("ICMPSeq")
        fields.append("ICMPotime")
        fields.append("ICMPrtime")
        fields.append("ICMPttime")

    '''
    # This one will basically show up in every single event, so we just ignore this.
    # No way to tell if this is a regular field from UDP or ICMP
    
    # icmp default
    if 'icmp-default' in args:
        regexstring += r'[^,]*'
        fields.append("ICMPType")
    '''

    regexstring += '$"'
    
    # print rule
    print("rule \"{}\"".format(" ".join(args)))
    print("when")
    print("  regex({}, to_string($message.message)).matches == true".format(regexstring))
    print("then")
    print("  let msg = concat(to_string($message.message), \",0\");")
    print("  let m = split(\",\", msg);")
    for x in range(0, len(fields)):
        print("  set_field(\"{}\", m[{}]);".format(fields[x], x))
    print("end")

genblock("pfSense-filterlog:", "ipv4", "tcp")
genblock("pfSense-filterlog:", "ipv4", "udp")
genblock("pfSense-filterlog:", "ipv4", "icmp-echo")
genblock("pfSense-filterlog:", "ipv4", "icmp-protocol-unreachable")
genblock("pfSense-filterlog:", "ipv4", "icmp-port-unreachable")
genblock("pfSense-filterlog:", "ipv4", "icmp-unreachable")
genblock("pfSense-filterlog:", "ipv4", "icmp-need-frag")
genblock("pfSense-filterlog:", "ipv4", "icmp-tstamp")
genblock("pfSense-filterlog:", "ipv4", "icmp-tstamp-reply")

genblock("pfSense-filterlog:", "ipv6", "tcp")
genblock("pfSense-filterlog:", "ipv6", "udp")
genblock("pfSense-filterlog:", "ipv6", "icmp-echo")
genblock("pfSense-filterlog:", "ipv6", "icmp-protocol-unreachable")
genblock("pfSense-filterlog:", "ipv6", "icmp-port-unreachable")
genblock("pfSense-filterlog:", "ipv6", "icmp-unreachable")
genblock("pfSense-filterlog:", "ipv6", "icmp-need-frag")
genblock("pfSense-filterlog:", "ipv6", "icmp-tstamp")
genblock("pfSense-filterlog:", "ipv6", "icmp-tstamp-reply")
