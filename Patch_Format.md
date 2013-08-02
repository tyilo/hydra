Patch location
==============

You should put all your patch files in the `~/patches` directory.

Patch format
============

The name of the file must match the name of the executable you want to patch.

Every line of the file should follow one of the following formats:
- Empty line -> ignored
- Starting with a `#` -> ignored
- Starting with `path` (case insensitive), following at least one whitespace character,
  and the path that the executable must have for the patch to be applied.
  
  If the path isn't specified in the patch file all executables with the same name as the filename will get patched.

- Starting with `sha1sum` (case insensitive), following at least one whitespace character,
  and the sha1sum the executable must have for the patch to be applied.
- All other lines should have the format `[address] [bytes]`
  where `[address]` is the address the patch should be applied to 
  and `[bytes]` are the bytes that should be patched. You can use whitespace between each byte.

  Both the address and the bytes should be in hexadecimal without a leading `0x`.

Example patch
=============
**Note:** This doesn't work currently due to ASLR.

Save as `~/patches/Activity Monitor`:
```
path    /Applications/Utilities/Activity Monitor.app/Contents/MacOS/Activity Monitor
sha1sum 081785e434baee1d1258e740e66234b4d181965b

# +[SMProcess setProcessName:]
0000000100009a9c 48B8C068030001000000 909090909090

# Hello @geekable from Tyilo at #osxre :^)
0000000100026853 48656c6c6f20406765656b61626c652066726f6d205479696c6f20617420236f73787265203a5e29 20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020 00
```

Load `hydra.kext` and fire up `hydra-userland`.

Wait a few seconds and then open Activity Monitor and you should see all the process names has been replaced.
