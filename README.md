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

Happy research!
