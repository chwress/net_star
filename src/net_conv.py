#!/usr/bin/env python3

import argparse
import os
import re
import sys
import typing

import util


__missing_bytes = re.compile(
    "\[[0-9]+ byte(s)? missing in capture file\]")


def parse(line: str, skip: bool):
    d = (util.Direction.RECV if line.startswith('\t') else util.Direction.SEND)
    line = line.strip()
    if not line:
        return None, None

    try:
        msg = ''.join(chr(int(line[i:i + 2], 16))
                      for i in range(0, len(line), 2))
    except ValueError:
        return None, None

    if skip:
        msg = __missing_bytes.sub("", msg)
    else:  # replace
        pass

    return d, msg


def process_file(fin: typing.IO, skip: bool):

    def _to_message(direction: util.Direction, msgs: typing.List[str]):
        return direction, ''.join(msgs)

    prev = []
    for line in fin:
        direction, msg = parse(line, skip)
        if not msg:
            continue

        try:
            if prev[0] == direction:
                prev.append(msg)

            else:
                yield _to_message(prev[0], prev[1:])
                prev = [direction, msg]

        except IndexError:
            # first line/ initialization
            prev = [direction, msg]

    if prev:
        yield _to_message(prev[0], prev[1:])


def main(inputs: typing.List[str], output: typing.Dict, skip: bool=False) -> int:
    ret = 0
    n = 0
    for fname in inputs:
        try:
            with open(fname, 'r') as fin:
                for d, msg in process_file(fin, skip):
                    for w in output[d]:
                        w.write_d(n, d, msg)

                    n += 1
        except Exception:
            sys.stderr.write(f"[!!] Couldn't process '{fname}'\n")
            ret += 1

    return ret


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, metavar="INPUT_FILENAME", nargs=1,
                        help="the names of the tshark output files to be processed")

    parser.add_argument("--skip-missingbytes", action="store_true", dest="skip", default=False,
                        help="indicates to skip rather than replace missing bytes")

    parser.add_argument("--send", metavar="FILENAME", type=str, default=None,
                        help="the name of the file to write outgoing messages to.")
    parser.add_argument("--recv", metavar="FILENAME", type=str, default=None,
                        help="the name of the file to write incoming messages to.")
    parser.add_argument("--both", metavar="FILENAME", type=str, default=None,
                        help="the name of the file to write incoming & outgoing messages to.")

    args = parser.parse_args()

    out = {
        util.Direction.RECV: [],
        util.Direction.SEND: []
    }

    if args.recv:
        out[util.Direction.RECV].append(util.Output.deduce_output(args.recv))

    if args.send:
        out[util.Direction.SEND].append(util.Output.deduce_output(args.send))

    if args.both:
        out[util.Direction.RECV].append(util.Output.deduce_output(args.both))
        out[util.Direction.SEND].append(util.Output.deduce_output(args.both))

    if out[util.Direction.RECV] == out[util.Direction.SEND] == []:
        o = util.RawTextFile(sys.stdout)
        out[util.Direction.RECV] = out[util.Direction.SEND] = [o]

    for fn in args.input:
        if not os.path.exists(fn):
            parser.error(f"the file '{fn}' does not exist! Abort.")

        if os.path.isdir(fn):
            parser.error(f"'{fn}' is a directory, but needs to be a file! Abort.")

    sys.exit(main(args.input, out, args.skip))
