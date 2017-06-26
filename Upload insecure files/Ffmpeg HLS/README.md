# FFmpeg HLS vulnerability
FFmpeg is an open source software used for processing audio and video formats. You can use a malicious HLS playlist inside an AVI video to read arbitrary files.

## Exploits
```
1. `./gen_xbin_avi.py file://<filename> file_read.avi`
2. Upload `file_read.avi` to some website that processes videofiles
3. (on server side, done by the videoservice) `ffmpeg -i file_read.avi output.mp4`
4. Click "Play" in the videoservice.
5. If you are lucky, you'll the content of `<filename>` from the server.
```

## Thanks to
* [Hackerone - Local File Disclosure via ffmpeg @sxcurity](https://hackerone.com/reports/242831)
* [PHDays - Attacks on video converters:a year later, Emil Lerner, Pavel Cheremushkin](https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.p)
* [Script by @neex](https://github.com/neex/ffmpeg-avi-m3u-xbin/blob/master/gen_xbin_avi.py)
