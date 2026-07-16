# Thanh Hoa 2 — LYKNCTF Writeup

## Challenge Information

- **Challenge:** Thanh Hoa 2
- **Category:** Forensics / Steganography
- **Provided file:** `lyknctf.mp4`

## Summary

The supplied MP4 was more than an ordinary music video. It contained:

1. An attached PNG image stored as an additional video stream.
2. An AES-encrypted ZIP archive appended to the end of the MP4.
3. The ZIP password hidden in the least significant bits of the attached PNG's RGB values.

Using the recovered password to decrypt the ZIP revealed the flag.

---

## 1. Inspecting the MP4

I first checked the streams inside the video with `ffprobe`:

```bash
ffprobe -v error -show_streams -show_format lyknctf.mp4
```

The file contained the expected H.264 video and AAC audio streams, but it also contained a third stream:

```text
index=2
codec_name=png
codec_type=video
width=1280
height=720
DISPOSITION:attached_pic=1
```

The `attached_pic=1` field showed that a PNG image had been embedded as cover artwork.

I extracted it with FFmpeg:

```bash
ffmpeg -i lyknctf.mp4 -map 0:2 -frames:v 1 attached.png
```

The resulting image appeared to be an ordinary blurred frame, so I checked it for hidden pixel data.

---

## 2. Extracting the LSB Message

I read the least significant bit of every RGB byte, grouped the bits into bytes, and decoded the result as ASCII:

```python
from pathlib import Path

import numpy as np
from PIL import Image

image = Image.open("attached.png").convert("RGB")
pixels = np.asarray(image, dtype=np.uint8)

# Read the least significant bit of every R, G, and B value.
bits = (pixels.reshape(-1) & 1).astype(np.uint8)

# Group every eight bits into one byte.
hidden_data = np.packbits(bits).tobytes()

print(hidden_data[:200].decode("ascii", errors="ignore"))
```

Output:

```text
NEMCHUATHANHHOA NEMCHUATHANHHOA NEMCHUATHANHHOA ...
```

The repeated hidden message gave the password:

```text
NEMCHUATHANHHOA
```

This translates to **Nem chua Thanh Hóa**, a specialty associated with Thanh Hóa, matching the challenge's theme.

---

## 3. Carving the Appended ZIP Archive

Searching the MP4 for file signatures revealed a ZIP local-file header near the very end of the file. The archive could be carved out with Python:

```python
from pathlib import Path

video = Path("lyknctf.mp4").read_bytes()
zip_offset = video.rfind(b"PK\x03\x04")

if zip_offset == -1:
    raise RuntimeError("ZIP signature not found")

Path("hidden.zip").write_bytes(video[zip_offset:])
print(f"ZIP found at offset {zip_offset}")
```

The carved archive contained one encrypted file:

```text
flag.txt
```

Because it used AES encryption, I extracted it with 7-Zip and the password recovered from the PNG:

```bash
7z x -pNEMCHUATHANHHOA hidden.zip
cat flag.txt
```

---

## Flag

```text
LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}
```

## Key Takeaways

- MP4 files can contain additional streams, including attached cover images.
- Valid data can be appended after a media container without preventing normal playback.
- LSB steganography hides information by modifying the lowest bit of pixel-channel values.
- Always inspect both the internal streams and the raw file signatures of suspicious media files.