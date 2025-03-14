<?php

namespace Vens\PcapParser;

class PcapParser
{
    // 从原始数据包中提取流五元组
    public static function flowtuple_from_raw($raw, $linktype = 1)
    {
        if ($linktype === 1) { // Ethernet
            $ip = substr($raw, 14);
            $sip = inet_ntop(substr($ip, 12, 4));
            $dip = inet_ntop(substr($ip, 16, 4));
            $proto = ord(substr($ip, 9, 1));
            if ($proto === 6 || $proto === 17) {
                $transport = substr($ip, (ord($ip[0]) & 0x0F) * 4);
                $sport = unpack('n', substr($transport, 0, 2))[1];
                $dport = unpack('n', substr($transport, 2, 2))[1];
            } else {
                $sport = 0;
                $dport = 0;
            }
        } else {
            $sip = 0;
            $dip = 0;
            $proto = -1;
            $sport = 0;
            $dport = 0;
        }
        return array($sip, $dip, $sport, $dport, $proto);
    }

    // 从原始数据包中提取有效负载
    public static function payload_from_raw($raw, $linktype = 1)
    {
        if ($linktype === 1) {
            $ip = substr($raw, 14);
            if (ord(substr($ip, 9, 1)) === 6 || ord(substr($ip, 9, 1)) === 17) {
                $transport = substr($ip, (ord($ip[0]) & 0x0F) * 4);
                $tcpUdpHeaderLength = (ord(substr($transport, 12, 1)) >> 4) * 4;
                return substr($transport, $tcpUdpHeaderLength);
            }
        }
        return "";
    }

    // 从 PCAP 数据包迭代器中提取属于同一流的所有数据包
    public static function next_connection_packets($fobj, $offset)
    {
        // 读取 PCAP 文件头（24 字节）
        $pcapHeader = fread($fobj, 24);
        $linktype = unpack('V', substr($pcapHeader, 20, 4))[1];

        // 定位到偏移量
        fseek($fobj, $offset);

        // 读取第一个数据包
        $packetHeader = fread($fobj, 16);
        if (strlen($packetHeader) < 16) {
            return;
        }
        $packetHeaderData = unpack('Vts_sec/Vts_usec/Vincl_len/Vorig_len', $packetHeader);
        $packetLength = $packetHeaderData['incl_len'];
        $packetData = fread($fobj, $packetLength);
        if (strlen($packetData) < $packetLength) {
            return;
        }
        $first_ft = self::flowtuple_from_raw($packetData, $linktype);
        yield array(
            "src" => $first_ft[0],
            "dst" => $first_ft[1],
            "sport" => $first_ft[2],
            "dport" => $first_ft[3],
            "raw" => base64_encode(self::payload_from_raw($packetData, $linktype)),
            "direction" => true
        );

        // 继续读取后续数据包
        while (!feof($fobj)) {
            $packetHeader = fread($fobj, 16);
            if (strlen($packetHeader) < 16) {
                break;
            }
            $packetHeaderData = unpack('Vts_sec/Vts_usec/Vincl_len/Vorig_len', $packetHeader);
            $packetLength = $packetHeaderData['incl_len'];
            $packetData = fread($fobj, $packetLength);
            if (strlen($packetData) < $packetLength) {
                break;
            }
            $ft = self::flowtuple_from_raw($packetData, $linktype);
            if (!($first_ft === $ft || $first_ft === array($ft[1], $ft[0], $ft[3], $ft[2], $ft[4]))) {
                break;
            }
            yield array(
                "src" => $ft[0],
                "dst" => $ft[1],
                "sport" => $ft[2],
                "dport" => $ft[3],
                "raw" => base64_encode(self::payload_from_raw($packetData, $linktype)),
                "direction" => $first_ft === $ft
            );
        }
    }


    public static function  getPacketList($fobj,$offset){
        $packetList = [];
        foreach (self::next_connection_packets($fobj, $offset) as $packet) {
            $packetList[] = $packet;
        }
        return $packetList;
    }
}