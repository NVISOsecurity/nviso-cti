rule RareEquities_KCP

{

    meta:

        author = "@stvemillertime"

        description = "This is a wide catchall rule looking for executables with equities for a transport library called KCP, https://github.com/skywind3000/kcp Matches on this rule may have built-in KCP transport ability."

    strings:

        $a01 = "[RO] %ld bytes"

        $a02 = "recv sn=%lu"

        $a03 = "[RI] %d bytes"

        $a04 = "input ack: sn=%lu rtt=%ld rto=%ld"

        $a05 = "input psh: sn=%lu ts=%lu"

        $a06 = "input probe"

        $a07 = "input wins: %lu"

        $a08 = "rcv_nxt=%lu\\n"

        $a09 = "snd(buf=%d, queue=%d)\\n"

        $a10 = "rcv(buf=%d, queue=%d)\\n"

        $a11 = "rcvbuf"

    condition:

        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 5MB and 3 of ($a*)

}
