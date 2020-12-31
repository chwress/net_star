import enum
import io
import os
import sys
import tarfile
import urllib.parse
import zipfile


class Direction(enum.Enum):
    RECV = "in"
    SEND = "out"


class Output():
    def __init__(self):
        pass

    def write_in(self, id_, s):
        self._write_ex(f"{id_}.{Direction.RECV.value}", s)

    def write_out(self, id_, s):
        self._write_ex(f"{id_}.{Direction.SEND.value}", s)

    def write_d(self, id_, d, s):
        if d == Direction.RECV:
            self.write_in(id_, s)

        elif d == Direction.SEND:
            self.write_out(id_, s)

        else:
            raise ValueError("Illegal specification of direction")

    def write(self, fname, s):
        self._write_ex(fname, s)

    def _write_ex(self, id_, s):
        raise RuntimeError("Not implemented")

    __outputs = {}

    @staticmethod
    def deduce_output(fname):
        try:
            return Output.__outputs[fname]
        except KeyError:
            if fname == "-" or not fname:
                Output.__outputs[fname] = RawTextFile(sys.stdout)
            elif fname.endswith(".zip"):
                Output.__outputs[fname] = ZipArchive(fname)
            elif fname.endswith(".tar.gz"):
                Output.__outputs[fname] = TarArchive(fname)
            else:
                Output.__outputs[fname] = TextFile(fname)

        return Output.__outputs[fname]


class ZipArchive(Output):
    def __init__(self, fname):
        self.__zf = zipfile.ZipFile(fname, 'w', zipfile.ZIP_DEFLATED)

    def __del__(self):
        self.__zf.close()

    def _write_ex(self, id_, s):
        data = s.encode('utf8') if isinstance(s, str) else s
        self.__zf.writestr(id_, data)


class TarArchive(Output):
    def __init__(self, fname):
        self.__tf = tarfile.open(fname, 'w:gz')

    def __del__(self):
        self.__tf.close()

    def _write_ex(self, id_, s):
        data = s.encode('utf8') if isinstance(s, str) else s
        info = tarfile.TarInfo(name=id_)
        info.size = len(data)

        self.__tf.addfile(info, io.BytesIO(data))


class RawTextFile(Output):
    def __init__(self, f):
        self._f = f

    def write_in(self, _, s):
        self._write_ex(None, f"<\t{urllib.parse.quote(s)}")

    def write_out(self, _, s):
        self._write_ex(None, f">\t{urllib.parse.quote(s)}")

    def write(self, fname, s):
        self._write_ex(fname, urllib.parse.quote(s))

    def _write_ex(self, _, s):
        self._f.write(s)
        self._f.write('\n')


class TextFile(RawTextFile):
    def __init__(self, fname):
        RawTextFile.__init__(self, open(fname, 'w'))

    def __del__(self):
        self._f.close()


def read_stats(fname):
    with open(fname, 'r') as f:
        for x in read_stats_ex(f):
            yield x


def read_stats_ex(f):
    def to_int(x):
        try:
            return int(x)
        except (TypeError, ValueError):
            return None

    for i, x in enumerate(f.readlines()):
        try:
            arr = x.strip().split(';')

            if len(arr) < 3:
                raise ValueError(f"We are expecting 3 or more fields, {len(arr)} given")

            else:
                # <frame number>, ..., <stream_id>
                arr[0] = to_int(arr[0])
                arr[-1] = to_int(arr[-1])
                yield tuple(arr)

        except Exception as e:
            raise ValueError(
                "Illegal format of line #{}: {}".format(i + 1, str(e)))
