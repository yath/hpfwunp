# HP Firmware Unpacker

Extracts a HP `.ful` (`@PJL ENTER LANGUAGE=FWUPDATE`) PCL file. Tested with
OfficeJet Pro 8620 firmware updates.

Most information is from the [*Unpacking HP Firmware Updates* blog post
series](https://www.jsof-tech.com/unpacking-hp-firmware-updates-part-1/) ([part
2](https://www.jsof-tech.com/unpacking-hp-firmware-updates-part-2/), [part
3](https://www.jsof-tech.com/unpacking-hp-firmware-updates-part-3/), [part
4](https://www.jsof-tech.com/unpacking-hp-firmware-updates-part-4/)), so all
credits goes to them.

Usage:

```shell
$ go run unpack.go -input_filename foo_nbx_signed.ful -output_prefix foo_nbx_signed.extracted
[…]
$ ls foo_nbx_signed.extracted.*
[…]
```

To dump the intermediate extraction results for debugging or further analysis,
set the `-intermediates_prefix` to a filename prefix they should be dumped to.
Also see the `-v` option to increase the log level.

The `ghidra_import.py` script can be used on the `.romnosi_text` image to load
additional segments. For headless usage, a `ghidra_import.properties` with the
text `Select metadata JSON OK = <path to app.json>` can be created in the same
directory and `analyzeHeadless` be invoked like:

```shell
$GHIDRA_DIR/support/analyzeHeadless <project dir> <project name> \
  -import foo.0x48...romnosi_text.bin \
  -processor ARM:BE:32:Cortex \
  -scriptPath $(pwd) \
  -propertiesPath $(pwd) \
  -preScript ghidra_import.py
```

Happy researching!
