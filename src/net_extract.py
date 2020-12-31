#!/usr/bin/env python3

import argparse
import enum
import os
import sys
import typing

import dpkt
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.tcp import TCP
from dpkt.udp import UDP

import util


class PayloadType(enum.Enum):
    ETHERNET = "ethernet"
    IP = "ip"
    TCP = "tcp"
    UDP = "udp"


def _read_frameids(stats_fnames):
    stats = set()
    if not isinstance(stats_fnames, list):
        stats_fnames = [stats_fnames]

    for fname in stats_fnames:
        stats.update(set(x[0]
                         for x in util.read_stats(fname) if x[0] is not None))

    return stats


def _read_streamids(stats_fnames):
    stats = dict()
    if not isinstance(stats_fnames, list):
        stats_fnames = [stats_fnames]

    for fname in stats_fnames:
        stats.update(dict((x[0], x[-1])
                          for x in util.read_stats(fname) if x[0] is not None and x[-1] is not None))

    return stats


def extract_payloads(data: typing.List[str], stats: typing.List[str], output: util.Output, ptype: PayloadType = PayloadType.IP, quiet: bool = False) -> int:
    if ptype == PayloadType.ETHERNET:
        def parse(x: bytes) -> dpkt.Packet:
            return Ethernet(x)

    elif ptype == PayloadType.IP:
        def parse(x: bytes) -> dpkt.Packet:
            p = Ethernet(x)
            if isinstance(p.data, IP):
                return p.data

            raise ValueError("Not an IP packet")

    elif ptype == PayloadType.UDP:
        def parse(x: bytes) -> dpkt.Packet:
            p = Ethernet(x)
            if isinstance(p.data, IP):
                if isinstance(p.data.data, UDP):
                    return p.data.data

            raise ValueError("Not an UDP packet")

    elif ptype == PayloadType.TCP:
        def parse(x: bytes) -> dpkt.Packet:
            p = Ethernet(x)
            if isinstance(p.data, IP):
                if isinstance(p.data.data, TCP):
                    return p.data.data

            raise ValueError("Not a TCP packet")

    else:
        raise ValueError("This shouldn't be happening")

    frames = _read_frameids(stats)

    frame_no = 1
    for fname in data:
        for _, buf in dpkt.pcap.Reader(open(fname, "rb")):

            try:
                if frame_no in frames:
                    pkt = parse(buf)
                    output.write(f"{frame_no:06d}", bytes(pkt.data))

            except Exception as e:
                if not quiet:
                    sys.stderr.write(f"Unable to process frame #{frame_no}: {str(e)}\n")

            frame_no += 1

    return 0


def extract_packets(data: typing.List[str], stats: typing.List[str], fn_out: str) -> int:
    if not fn_out:
        return 0

    if len(data) != len(stats):
        return 2

    out = None
    for fn_in, fn_stats in zip(data, stats):
        frames = _read_frameids(fn_stats)
        try:
            pcap = dpkt.pcap.Reader(open(fn_in, "rb"))
            if out is None:
                out = dpkt.pcap.Writer(open(fn_out, "wb"),
                                       linktype=pcap.datalink())

            elif out.datalink() != pcap.datalink():
                raise ValueError("Mismatching datalink specifications")

            frame_no = 1

            for ts, pkt in pcap:
                try:
                    if frame_no in frames:
                        out.writepkt(pkt, ts)

                except Exception:
                    sys.stderr.write(f"Unable to write frame #{frame_no}\n")

                frame_no += 1

        except Exception as e:
            sys.stderr.write(f"Something is wrong: {str(e)}\n")
            return 1

        finally:
            if out is not None:
                out.close()

    return 0


def extract_streams(data: typing.List[str], stats: typing.List[str], fn_out: str) -> int:
    if not fn_out:
        return 0

    if len(data) != len(stats):
        return 2

    def __gen_outputdict(stats: dict, fn_outprefix: str, linktype: int=dpkt.pcap.DLT_EN10MB):
        for stream_id in set(stats.values()):
            w = dpkt.pcap.Writer(open(f"{fn_outprefix}{stream_id}.pcap", 'wb'), linktype=linktype)
            yield stream_id, w

    out = None
    for fn_in, fn_stats in zip(data, stats):
        try:
            sids = _read_streamids(fn_stats)
            pcap = dpkt.pcap.Reader(open(fn_in, "rb"))
            out = dict(__gen_outputdict(sids, fn_out, pcap.datalink()))

            frame_no = 1

            for ts, pkt in pcap:
                try:
                    stream_id = sids[frame_no]
                    try:
                        # check if it has a Linux cooked capture
                        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                            eth = dpkt.sll.SLL(pkt)
                        else:
                            eth = dpkt.ethernet.Ethernet(pkt)

                        out[stream_id].writepkt(eth, ts)
                    except Exception:
                        sys.stderr.write(f"Unable to write frame #{frame_no}\n")

                except KeyError:
                    pass

                frame_no += 1

        except StopIteration:
            pass

        except Exception as e:
            sys.stderr.write(f"Something is wrong: {str(e)}\n")
            return 1

        finally:
            if out is not None:
                for x in out.values():
                    x.close()

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    # We want the subcommmand to be the very first parameters. Consequently,
    # we add the common parameters for each subparser.
    def common_parameters(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("input", type=str, metavar="PCAP_FILENAME", nargs=1,
                            help="the pcap fileto be processed.")
        parser.add_argument("stats", type=str, nargs=1, metavar="STATISTICS_FILENAME",
                            help="the name of the corresponding `net_stats` statistics files.")
        parser.add_argument("-q", "--quiet", action="store_true", dest="quiet", default=False,
                            help="do not report warnings.")

    # extract payloads
    payloads = sub.add_parser("payloads")
    common_parameters(payloads)

    action = payloads.add_mutually_exclusive_group(required=True)
    action.add_argument("--ethernet", action="store_true", dest="ethernet", default=False,
                        help="extract the Ethernet payload.")
    action.add_argument("--ip", action="store_true", dest="ip", default=False,
                        help="extract the IP payload.")
    action.add_argument("--tcp", action="store_true", dest="tcp", default=False,
                        help="extract the TCP payload.")
    action.add_argument("--udp", action="store_true", dest="udp", default=False,
                        help="Extract the UDP payload.")
    payloads.add_argument("--out", metavar="FILENAME", type=str, default="-",
                          help="the name of the file to write payloads to.")

    # extract packets
    packets = sub.add_parser("packets")
    common_parameters(packets)

    packets.add_argument("--out", action="store", type=str, metavar="FILE", dest="out",
                         help="the pcap file to write the output to.", default=None, required=True)

    # extract streams
    streams = sub.add_parser("streams")
    common_parameters(streams)

    streams.add_argument("--out-prefix", action="store", type=str, metavar="FILE", dest="out",
                         help="The filename prefix for pcaps file to write individual streams to.", required=True)

    args = parser.parse_args()

    if len(args.input) != len(args.stats):
        parser.error(f"you need to specify as many stats as input files! Abort.")

    for fn in args.input + args.stats:
        if not os.path.exists(fn):
            parser.error(f"the file '{fn}' does not exist! Abort.")

        if os.path.isdir(fn):
            parser.error(f"'{fn}' is a directory, but needs to be a file! Abort.")

    def main(args: argparse.Namespace) -> int:
        if args.cmd == "payloads":
            out = util.Output.deduce_output(args.out)
            if args.ethernet:
                ptype = PayloadType.ETHERNET
            elif args.ip:
                ptype = PayloadType.IP
            elif args.tcp:
                ptype = PayloadType.TCP
            elif args.udp:
                ptype = PayloadType.UDP

            return extract_payloads(args.input, args.stats, out, ptype, args.quiet)

        elif args.cmd == "packets":
            return extract_packets(args.input, args.stats, args.out)

        elif args.cmd == "streams":
            return extract_streams(args.input, args.stats, args.out)

    sys.exit(main(args))
