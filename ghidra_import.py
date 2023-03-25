# HP firmware segment loader
#@author yath
#@category Import
#@keybinding
#@menupath
#@toolbar

import json
import sys

from ghidra.program.database.module import TreeManager
from ghidra.program.flatapi import FlatProgramAPI

from java.io import File, FileInputStream
from java.nio.charset import Charset
from java.nio.file import Files

FLASH_SECTION = ".romnosi_text"

def get_metadata():
    f = askFile("Select metadata JSON", "OK")
    p = f.toPath()
    j = "\n".join(Files.readAllLines(p, Charset.forName("UTF-8")))
    meta = json.loads(j)
    return meta, p

def get_segment_for_section(meta, name):
    s = [s for s in meta['memory']['segments'] if s['section_info']['name'] == name]
    if len(s) != 1:
        raise Exception("found %d memory sections named %r, want exactly 1", len(s), name)
    return s[0]

def get_file_bytes(mem, fn, json_path):
    f = File(json_path.resolveSibling(fn).toUri())
    return mem.createFileBytes(fn, 0, f.length(), FileInputStream(f), getMonitor())

def main():
    try:
        file = askFile("Please specify %s image to import" % (FLASH_SECTION,), "Import")
        lang = getLanguage(ghidra.program.model.lang.LanguageID("ARM:BE:32:Cortex"))
        comp = lang.getDefaultCompilerSpec()
        program = importFileAsBinary(file, lang, comp)
    except:
        program = currentProgram

    txn = program.startTransaction("Import program")

    meta, path = get_metadata()
    flash_seg = get_segment_for_section(meta, FLASH_SECTION)

    mem = program.getMemory()
    addr = mem.getMinAddress().getNewAddress(flash_seg['start_address'])
    mem.moveBlock(mem.getBlocks()[0], addr, getMonitor())

    frag = program.getTreeManager().getFragment(TreeManager.DEFAULT_TREE_NAME, addr)
    frag.setName(FLASH_SECTION)

    for seg in meta['memory']['segments']:
        si = seg['section_info']
        li = seg['load_info']
        name = si['name']
        if name == FLASH_SECTION:
            continue

        addr = addr.getNewAddress(seg['start_address'])
        if li['all_zeros']:
            print("Adding zeros block at %s" % (addr,))
            block = mem.createInitializedBlock(name, addr, si['size'], 0, getMonitor(), False)
        elif li['flash_source_start'] != 0:
            print("Adding mapped block at %s" % (addr,))
            mapped_addr = addr.getNewAddress(li['flash_source_start'])
            assert si['size'] == li['flash_source_len']
            block = mem.createByteMappedBlock(name, addr, mapped_addr, si['size'], False)
        else:
            print("Adding file block at %s" % (addr,))
            fb = get_file_bytes(mem, li['filename'], path)
            assert si['size'] == fb.getSize()
            block = mem.createInitializedBlock(name, addr, fb, 0, fb.getSize(), False)

        flags = si['flags']
        block.setComment("Flags: 0x%x" % (flags,))
        if flags == 1:
            block.setRead(True)
            block.setExecute(True)
        elif flags == 2:
            block.setRead(True)
        else:
            # FIXME
            print("Unknown block flags 0x%x, assuming RWX" % (flags,))
            block.setRead(True)
            block.setWrite(True)
            block.setExecute(True)

    flat = FlatProgramAPI(program)
    entry = addr.getNewAddress(meta['entry_point'])
    flat.addEntryPoint(entry)
    flat.createLabel(entry, "_start", True)

    program.endTransaction(txn, True)
    openProgram(program)

try:
    main()
except:
    print("Error: %s" % (sys.exc_info()[0],))
    raise
