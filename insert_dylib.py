import sys
import struct
from macholib.mach_o import *
from macholib.util import fileview
from macholib.ptypes import sizeof

def ROUND_UP(x, y):
    return (((x) + (y) -1) & -(y))

def dump_macho(binary_path, dylib_path):
    with open(binary_path, "r+b") as fp:
        assert fp.tell() == 0
        fp.seek(0, 2) # 0 displace from the end
        file_size = [fp.tell()] # why array? Because Python doesn't allow pass by referrence with Int ¯\_(ツ)_/¯
        fp.seek(0, 0) # 0 displace from the start
        header = struct.unpack(">I", fp.read(4))[0] # < for little endian, 4 because sizeof(uint32_t) which is 4 bytes
        if (header == MH_MAGIC_64 or header == MH_CIGAM_64 or header == MH_MAGIC or header == MH_CIGAM):
            insert_dylib(fp, 0, dylib_path, file_size)    
        elif (header == FAT_MAGIC or header == FAT_CIGAM):
            print("Implement later")

def check_load_commands(fh, mh, header_offset, commands_offset, dylib_path, slice_size, kw):
    """
    The idea is make sure the CODE_SIGNATURE is the last one in the LC
    """
    fh.seek(commands_offset, 0)
    linkedit_32_pos = -1
    linkedit_32 = None
    linkedit_64_pos = -1
    linkedit_64 = None
    symtab_pos = -1
    symtab_size = 0
    for i in range(mh.ncmds):
        cmd_load = load_command.from_fileobj(fh, **kw)
        if (cmd_load.cmd == LC_CODE_SIGNATURE):
            if (i == mh.ncmds - 1):
                # Get CODE_SIGNATURE segment 
                klass = LC_REGISTRY.get(cmd_load.cmd, None)
                cmd_cmd = klass.from_fileobj(fh, **kw)
                dataoff = cmd_cmd.dataoff
                datasize = cmd_cmd.datasize
                fh.seek(-sizeof(klass), 1)
                # Zero out everything
                fh.seek(-8, 1)
                for j in range(cmd_load.cmdsize):
                    fh.write(b'\x00')

                linkedit_fileoff = 0
                linkedit_filesize = 0
                if (linkedit_64_pos != -1 and linkedit_64 is not None):
                    linkedit_fileoff = linkedit_64.fileoff
                    linkedit_filesize = linkedit_64.filesize
                elif (linkedit_32_pos != -1 and linkedit_32 is not None):
                    print("Placeholder for 32 bit")
                else:
                    print("warning: __LINKEDIT segment not found.")
                if (linkedit_32_pos != -1 or linkedit_64_pos != -1):
                    # Check if the linkedit really coves the whole file size
                    if (linkedit_fileoff + linkedit_filesize != slice_size[0]):
                        print("Warning: __LINKEDIT segment is not at the end of the file, so codesign will not work on the patched binary.")
                    else:
                        if (dataoff + datasize != slice_size[0]):
                            print("Warning: Codesignature is not at the end of __LINKEDIT segment, so codesign will not work on the patched binary.")
                        else:
                            slice_size[0] = slice_size[0] - datasize
                            if (symtab_pos == -1):
                                print("Warning: LC_SYMTAB load command not found. Codesign might not work on the patched binary.")
                            else:
                                fh.seek(symtab_pos+8, 0)
                                cmd_cmd = read_struct(fh, LC_REGISTRY.get(LC_SYMTAB, None), **kw)
                                diff_size = cmd_cmd.stroff + cmd_cmd.strsize - slice_size[0]
                                if (-0x10 <= diff_size and diff_size <= 0):
                                    cmd_cmd.strsize = cmd_cmd.strsize - diff_size
                                    fh.seek(symtab_pos+8, 0)
                                    fh.write(cmd_cmd.to_str())
                                else:
                                    print("Warning: String table doesn't appear right before code signature, codesign might not work on the patched binary.")
                            linkedit_filesize = linkedit_filesize - datasize
                            linkedit_vmsize = ROUND_UP(linkedit_filesize, 0x1000)
                            if (linkedit_32_pos != -1):
                                linkedit_32.filesize = linkedit_filesize
                                linkedit_32.vmsize = linkedit_vmsize
                                fh.seek(linkedit_32_pos + 8, 0)
                                fh.write(linkedit_32.to_str())
                            if (linkedit_64_pos != -1):
                                linkedit_64.filesize = linkedit_filesize
                                linkedit_64.vmsize = linkedit_vmsize
                                fh.seek(linkedit_64_pos + 8, 0)
                                fh.write(linkedit_64.to_str())
                            mh.ncmds = mh.ncmds - 1
                            mh.sizeofcmds = mh.sizeofcmds - cmd_load.cmdsize
                            return True
            else:   
                print("Warning: LC_CODE_SIGNATURE is not the last load command, so couldn't remove.")      
                
               
        elif (cmd_load.cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB)):
            # Check if the DYLIB already existed or not
            klass = LC_REGISTRY.get(cmd_load.cmd, None)
            cmd_cmd = klass.from_fileobj(fh, **kw)
            # data is a raw str
            data_size = cmd_load.cmdsize - sizeof(klass) - sizeof(load_command)
            cmd_data = fh.read(data_size)
            if (cmd_data.decode().rstrip("\x00") == dylib_path):
                return False    # If dylib_path already existed, return false
            fh.seek(-sizeof(klass)-data_size, 1)
        elif (cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64)):
            if (cmd_load.cmd == LC_SEGMENT):
                print("Placeholder")
            else:
                klass = LC_REGISTRY.get(cmd_load.cmd, None)
                cmd_cmd = klass.from_fileobj(fh, **kw)
                # print(cmd_cmd.segname.decode())
                if (cmd_cmd.segname.decode().rstrip("\x00") == "__LINKEDIT"):
                    linkedit_64_pos = fh.tell() - sizeof(klass) - 8
                    linkedit_64 = cmd_cmd
                    # print("linkedit_64_post: {}".format(hex(linkedit_64_pos)))
                fh.seek(-sizeof(klass), 1)
        elif (cmd_load.cmd == LC_SYMTAB):
            symtab_pos = fh.tell() - 8
            symtab_size = cmd_load.cmdsize
            # print("symtab_pos: {}".format(hex(symtab_pos)))
        fh.seek(cmd_load.cmdsize-8, 1) # -8 for cmd and cmdsize. This one helps to iterate to next LC section
        
    return True

def insert_dylib(fp, header_offset, dylib_path, slice_size):
    fp.seek(header_offset, 0)
    fh = fileview(fp, header_offset, slice_size[0])
    endianess = "<"
    kw = {"_endian_": endianess}
    # Get mach_header
    header = mach_header_64.from_fileobj(fh, **kw)
    commands_offset = header_offset + sizeof(mach_header_64)
    cont = check_load_commands(fh, header, header_offset, commands_offset, dylib_path, slice_size, kw)
    if (not cont):
        return True
    
    # Prepare the struct to write
    path_padding = 8
    dylib_path_len = len(dylib_path)
    dylib_path_size = (dylib_path_len & ~(path_padding - 1)) + path_padding
    cmdsize = sizeof(dylib_command) + 8 + dylib_path_size # + 8 because the type of LC and size of LC section
    dylib_cmd = struct.pack(endianess + "IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 0, 0, 0) # 24 is offset of string from the start of the section
    fh.seek(commands_offset + header.sizeofcmds, 0)
    fh.write(dylib_cmd)
    # Now we write the string
    diff_size = dylib_path_size - dylib_path_len
    dylib_path_encode = dylib_path.encode()
    for i in range(0, diff_size):
        dylib_path_encode = dylib_path_encode + b'\x00'
    fh.write(dylib_path_encode)
    # increase the ncmds of mach_header
    header.ncmds = header.ncmds + 1
    header.sizeofcmds = header.sizeofcmds + cmdsize
    fh.seek(header_offset, 0)
    fh.write(header.to_str())
    return True

if (len(sys.argv) == 3):
    dump_macho(sys.argv[1], sys.argv[2])
else:
    print("insert_dylib file_name dylib_path")
