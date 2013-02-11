#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) 2013 Frederic Gidouin
#
""" Extract threaddump from an hprof file.
    according to http://java.net/downloads/heap-snapshot/hprof-binary-format.html
"""

import optparse
import os
import struct
import sys
import time

def parseargs(argv):
    """ Parse commandline options.

    Returns (options, parameters).
    """

    parser = optparse.OptionParser()
    parser.usage = "usage: %prog [options] hprof_file"
    parser.add_option("-v", "--verbose", dest="verbose",
        default=0, action="store_true",
        help="increase verbosity")
    
    (opts, args) = parser.parse_args()

    if not args:
        print "hprof filename mandatory"
        sys.exit(1)

    return (opts, args)

class StackFrame:
    id = None
    method_id = None
    signature_id = None
    source_id = None
    class_serial = None
    line_number = 0

class StackTrace:
    serial = None
    thread_serial = None
    nb_frames = None
    frame_ids = None


def main(argv):
    (opts, args) = parseargs(argv)

    # define a vprint function for (optional) verbose printing

    if opts.verbose:
        def vprint(*args):
            for arg in args:
                print arg,
            print
    else:
        def vprint(*args):
            None

    # scan hprof file

    with open(args[0], "rb") as f:

        # read format header
        format = ""
        b = f.read(1)
        while ord(b): format += b; b = f.read(1)    # read null-terminated string
        sizeid = struct.unpack('>i', f.read(4))[0]     # big-endian size of identifiers
        epoch_ms = struct.unpack(">q", f.read(8))[0]
        print format, time.strftime("%Y%m%d %H:%M:%S", time.gmtime(epoch_ms / 1000))
        
        print "sizeof(ID)=", sizeid
        if sizeid != 4:
            print "unable to process hprof when sizeof(ID) is not 4"
            sys.exit(2)

        offset_records = f.tell()

        nb_strings = 0
        nb_classes = 0
        frames = {}
        traces = {}
        toresolve = {}  # strings to resolve
        s = {}   # resolved strings
        classes = {}

        #
        # loop hprof records for stack frames and stack traces
        #

        remaining = True
        tag = ord(f.read(1))

        while remaining:
            record_time = struct.unpack('>i', f.read(4))[0]
            length = struct.unpack('>i', f.read(4))[0]
            #print "tag:", tag, 'time:', record_time, 'length:', length

            if tag == 1:    # String in UTF-8
                f.seek(length, os.SEEK_CUR)
                nb_strings = nb_strings + 1
            elif tag == 4:  # stack frame
                frame = StackFrame()
                frame.id = struct.unpack(">i", f.read(4))[0]
                frame.method_id = struct.unpack(">i", f.read(4))[0]
                frame.signature_id = struct.unpack(">i", f.read(4))[0]
                frame.source_id = struct.unpack(">i", f.read(4))[0]
                frame.class_serial = struct.unpack(">i", f.read(4))[0]
                frame.line_number  = struct.unpack(">i", f.read(4))[0]
                frames[frame.id] = frame
                toresolve[frame.method_id] = None
                toresolve[frame.signature_id] = None
                toresolve[frame.source_id] = None
                #print "stack frame", frame #"id:", stack_frame_id, "method_name_id:", method_name_id, "method_signature_id:", method_signature_id
                
            elif tag == 5:  # stack trace
                trace = StackTrace()
                trace.serial = struct.unpack(">i", f.read(4))[0]
                trace.thread_serial = struct.unpack(">i", f.read(4))[0]
                trace.nb_frames = struct.unpack(">i", f.read(4))[0]
                trace.frame_ids = []
                for i in range(trace.nb_frames):
                    trace.frame_ids.append(struct.unpack(">i", f.read(4))[0])
                #print "stack trace", "stack_serial:", stack_serial, "thread_serial:", thread_serial, "nb_frames:", nb_frames
                #if trace.nb_frames > 0:
                #    f.seek(trace.nb_frames * sizeid, os.SEEK_CUR)

                #f.seek(length, os.SEEK_CUR)
                traces[trace.serial] = trace
            elif tag == 2:   # load class
                nb_classes = nb_classes + 1
                class_serial = struct.unpack(">i", f.read(4))[0]
                classobject_id = struct.unpack(">i", f.read(4))[0]
                stacktrace_serial = struct.unpack(">i", f.read(4))[0]
                classname_id = struct.unpack(">i", f.read(4))[0]
                toresolve[classobject_id] = None
                toresolve[classname_id] = None
                classes[class_serial] = classname_id
                #f.seek(length, os.SEEK_CUR)
            elif tag == 0x0c or tag == 0x1c: # heap dump, head dump segment
                vprint("dump segment of size", length)
                f.seek(length, os.SEEK_CUR)
            else:
                print "*** Unknown tag ", tag, " In file"
                f.seek(length, os.SEEK_CUR)

            byte = f.read(1)
            if byte:
                tag = ord(byte)
            else:
                remaining = False

        print len(frames), "stack frames out of", len(traces), "stack traces"

        #
        # resolve strings
        #

        print "resolving", len(toresolve), "strings out of", nb_strings, "entries in the hprof dump"
        f.seek(offset_records)

        remaining = True
        tag = ord(f.read(1))
        while remaining:
            record_time = struct.unpack('>i', f.read(4))[0]
            length = struct.unpack('>i', f.read(4))[0]
            if tag == 1:
                string_id = struct.unpack(">i", f.read(4))[0]
                string = f.read(length - 4)
                if string_id in toresolve:
                    del toresolve[string_id]
                    s[string_id] = string
            else:
                f.seek(length, os.SEEK_CUR)

            byte = f.read(1)
            if byte:
                tag = ord(byte)
            else:
                remaining = False

        if len(toresolve) > 0:
            print "*** Unable to resolve", len(toresolve), "string(s):", toresolve

        #
        # report stack traces
        #

        for i, st in traces.iteritems():
            print "thread", st.serial, "frames:", len(st.frame_ids)
            for frame_id in st.frame_ids:
                frame = frames[frame_id]
                method = s[frame.method_id]
                signature = s[frame.signature_id]
                source = s.get(frame.source_id, "unknown source")
                print "\t", s[classes[frame.class_serial]], method, signature, source, ":", frame.line_number

        print nb_classes

if __name__ == "__main__":
	main(sys.argv)