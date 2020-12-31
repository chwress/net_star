#!/usr/bin/env python3

import argparse
import os
import re
import sys
import typing

import util


def _filter_streams(fstats: typing.IO, regex: re.Pattern, incl: bool, strict: bool) -> int:
    def to_csv(arr, separator=';'):
        return separator.join(str(x) for x in arr)

    # 1st pass
    if incl:
        stream_ids = set(
            x[-1] for x in util.read_stats_ex(fstats) if regex.findall(to_csv(x)))

        # (optional) 2nd pass
        if strict:
            rm = set()

            fstats.seek(0)
            for x in util.read_stats_ex(fstats):
                if x[-1] in stream_ids and not regex.findall(to_csv(x)):
                    rm.add(x[-1])

            stream_ids -= rm

    else:
        stream_ids = set()
        excl = set()

        for x in util.read_stats_ex(fstats):
            stream_ids.add(x[-1])
            if regex.findall(to_csv(x)):
                excl.add(x[-1])

        stream_ids -= excl

    # 2nd/ 3rd pass
    fstats.seek(0)
    for s in util.read_stats_ex(fstats):
        if s[-1] in stream_ids:
            yield ';'.join(str(x) for x in s)

    return 0


def main(inputs: typing.List[str], out: typing.IO, regex: re.Pattern, incl: bool = True, strict: bool = False) -> int:
    ''' Filters the given statistics consisting of

       <frame_no>;<src_port>;<dst_port>;<protocol>;<stream_id>

       per stream.

       Packets that do not match a given regular expression, but
       reside in the same stream are included/ excluded.

       ATTENTION! If you need to filter such statistics per
       packets simply use grep ;)
       '''

    for fname in inputs:
        with open(fname, 'r') as fstats:
            for line in _filter_streams(fstats, regex, incl, strict):
                out.write(line)
                out.write('\n')

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, metavar="INPUT_FILENAME", nargs=1,
                        help="the names of the `net_stats` statistics files to be filtered")

    parser.add_argument("regex", metavar="REGEX", action="store", type=str,
                        help="The regex to filter the filter the input lines.")

    action = parser.add_mutually_exclusive_group()
    action.add_argument("--incl", action="store_true", dest="incl", default=False,
                        help="the filtered lines should be included in the output (default).")
    action.add_argument("--excl", action="store_true", dest="excl", default=False,
                        help="the filtered lines should be excluded from the output.")

    parser.add_argument("--strict", action="store_true", default=False,
                        help="any stream that contains packets that do not match the regex is completely excluded from the output.")
    parser.add_argument("--out", metavar="FILENAME", default=None,
                        help="the name of the file to write the filtered lines to (default: stdout).")

    args = parser.parse_args()

    if not args.excl:
        args.incl = True

    try:
        regex = (None if args.regex == None else re.compile(args.regex))
    except Exception as e:
        parser.error(f"illegal filter {str(e)}! Abort.")

    for fn in args.input:
        if not os.path.exists(fn):
            parser.error(f"the file '{fn}' does not exist! Abort.")

        if os.path.isdir(fn):
            parser.error(f"'{fn}' is a directory, but needs to be a file! Abort.")

    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, 'w') as fout:
            sys.exit(main(args.input, fout, regex, args.incl))

    else:
        sys.exit(main(args.input, sys.stdout, regex, args.incl))
