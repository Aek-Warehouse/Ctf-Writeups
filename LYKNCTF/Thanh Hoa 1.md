# LYKNCTF 2026 — Thanh Hoa 1

**Category:** Forensics / Steganography   
**Flag:** `LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}`

## Challenge

The challenge provided a single MP4 file:

```text
lyknctf.mp4
```

Since the video played normally, the first step was to check whether any additional files had been appended to it.

## 1. Find the hidden ZIP archive

Running `binwalk` on the video reveals a ZIP archive near the end of the file:

```bash
binwalk lyknctf.mp4
```

The ZIP begins at byte offset `31910541` (`0x1E6EA8D`).

It can be extracted automatically:

```bash
binwalk -e lyknctf.mp4
```

Alternatively, it can be carved manually with `dd`:

```bash
dd if=lyknctf.mp4 of=hidden.zip bs=1 skip=31910541
```

Listing the archive shows an encrypted file:

```bash
7z l hidden.zip
```

```text
flag.txt
```

The ZIP requires a password, so the next step is to inspect the video's audio.

## 2. Extract the audio

Extract the audio track from the MP4:

```bash
ffmpeg -i lyknctf.mp4 -vn -ac 1 audio.wav
```

The audio sounds like an ordinary song, but viewing it as a spectrogram reveals hidden text.

This can be done in Audacity:

1. Open `audio.wav`.
2. Change the track display from **Waveform** to **Spectrogram**.
3. Zoom into approximately the **6000–12000 Hz** frequency range.

Large letters appear across the spectrogram:

```text
RAUMAPHATAU
```

The same text is repeated throughout the audio.

Therefore, the ZIP password is:

```text
RAUMAPHATAU
```

## 3. Decrypt the archive

Extract the ZIP using the spectrogram text as the password:

```bash
7z x hidden.zip -pRAUMAPHATAU
```

The extracted `flag.txt` contains:

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```

## Flag

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```